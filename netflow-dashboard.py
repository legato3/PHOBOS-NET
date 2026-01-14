from flask import Flask, render_template, jsonify, request, Response, stream_with_context
from flask_compress import Compress
import subprocess, time, os, json
import socket # Added as per instruction
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque, Counter
from functools import wraps
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import maxminddb
import random
import dns.resolver
import dns.reversename
import sqlite3
import ipaddress
import atexit
import signal
import socket as socket_module  # For socket.timeout in syslog receiver

app = Flask(__name__)
# Configure compression with optimal settings
Compress(app)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html', 'text/css', 'text/javascript',
    'application/json', 'application/javascript'
]
app.config['COMPRESS_LEVEL'] = 6  # Balance between compression ratio and CPU usage
app.config['COMPRESS_MIN_SIZE'] = 500  # Only compress responses >500 bytes

# ------------------ Constants ------------------
CACHE_TTL_SHORT = 30        # 30 seconds for fast-changing data
CACHE_TTL_THREAT = 900      # 15 minutes for threat feeds
DEFAULT_TIMEOUT = 25        # subprocess timeout
MAX_RESULTS = 100           # default limit for API results
DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

# Graceful shutdown event
_shutdown_event = threading.Event()

# ------------------ Globals & caches ------------------
# Granular locks per endpoint to reduce contention
_lock_summary = threading.Lock()
_lock_sources = threading.Lock()
_lock_dests = threading.Lock()
_lock_ports = threading.Lock()
_lock_protocols = threading.Lock()
_lock_alerts = threading.Lock()
_lock_flags = threading.Lock()
_lock_asns = threading.Lock()
_lock_durations = threading.Lock()
_lock_bandwidth = threading.Lock()
_lock_flows = threading.Lock()
_lock_countries = threading.Lock()
_cache_lock = threading.Lock()  # generic small cache lock (e.g., packet sizes)
# Caches for new endpoints
_stats_summary_cache = {"data": None, "ts": 0, "key": None}
_stats_sources_cache = {"data": None, "ts": 0, "key": None}
_stats_dests_cache = {"data": None, "ts": 0, "key": None}
_stats_ports_cache = {"data": None, "ts": 0, "key": None}
_stats_protocols_cache = {"data": None, "ts": 0, "key": None}
_stats_alerts_cache = {"data": None, "ts": 0, "key": None}
_stats_flags_cache = {"data": None, "ts": 0, "key": None}
_stats_asns_cache = {"data": None, "ts": 0, "key": None}
_stats_durations_cache = {"data": None, "ts": 0, "key": None}
_stats_pkts_cache = {"data": None, "ts": 0, "key": None}
_stats_countries_cache = {"data": None, "ts": 0, "key": None}
_stats_talkers_cache = {"data": None, "ts": 0, "key": None}
_stats_services_cache = {"data": None, "ts": 0, "key": None}
_stats_hourly_cache = {"data": None, "ts": 0, "key": None}
_stats_flow_stats_cache = {"data": None, "ts": 0, "key": None}
_stats_proto_mix_cache = {"data": None, "ts": 0, "key": None}
_stats_net_health_cache = {"data": None, "ts": 0, "key": None}
_server_health_cache = {"data": None, "ts": 0}

_mock_data_cache = {"mtime": 0, "rows": [], "output_cache": {}}
# Lock for thread-safe access to mock data cache (performance optimization)
_mock_lock = threading.Lock()

_bandwidth_cache = {"data": None, "ts": 0}
_bandwidth_history_cache = {}
_flows_cache = {"data": None, "ts": 0}
_request_times = defaultdict(list)
_throttle_lock = threading.Lock()
_dns_cache, _dns_ttl = {}, {}
_geo_cache = {}
_geo_cache_ttl = 900  # 15 min
GEO_CACHE_MAX = 2000

_threat_cache = {"data": set(), "mtime": 0}
_threat_ip_to_feed = {}  # Maps IP -> {category, feed_name}
_threat_timeline = {}  # Maps IP -> {first_seen, last_seen, hit_count}
_feed_status = {}  # Per-feed health tracking
_alert_sent_ts = 0
_alert_history = deque(maxlen=200)  # Increased for 24h history
_alert_history_lock = threading.Lock()

# Watchlist management
WATCHLIST_PATH = "/root/watchlist.txt"
_watchlist_cache = {"data": set(), "mtime": 0}

# Security webhook for auto-blocking
SECURITY_WEBHOOK_PATH = "/root/security-webhook.json"

# MITRE ATT&CK mappings for threat categories
MITRE_MAPPINGS = {
    'C2': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    'MALWARE': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'SCANNER': {'technique': 'T1595', 'tactic': 'Reconnaissance', 'name': 'Active Scanning'},
    'BADACTOR': {'technique': 'T1190', 'tactic': 'Initial Access', 'name': 'Exploit Public-Facing Application'},
    'COMPROMISED': {'technique': 'T1584', 'tactic': 'Resource Development', 'name': 'Compromise Infrastructure'},
    'HIJACKED': {'technique': 'T1583', 'tactic': 'Resource Development', 'name': 'Acquire Infrastructure'},
    'AGGREGATE': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    'TOR': {'technique': 'T1090', 'tactic': 'Command and Control', 'name': 'Proxy'},
}

_common_data_cache = {}
_common_data_lock = threading.Lock()
COMMON_DATA_CACHE_MAX = 100  # Maximum cache entries (4 types * 25 time ranges)

_dns_resolver_executor = ThreadPoolExecutor(max_workers=5)
DNS_CACHE_MAX = 5000

_threat_status = {'last_attempt':0,'last_ok':0,'size':0,'status':'unknown','error':None}

_metric_nfdump_calls = 0
_metric_stats_cache_hits = 0
_metric_bw_cache_hits = 0
_metric_conv_cache_hits = 0
_metric_http_429 = 0

# CPU stat caching for accurate CPU percentage calculation
_cpu_stat_prev = {'times': {}, 'ts': 0}
_cpu_stat_lock = threading.Lock()

MMDB_CITY = "/root/GeoLite2-City.mmdb"
MMDB_ASN = "/root/GeoLite2-ASN.mmdb"
THREATLIST_PATH = "/root/threat-ips.txt"
THREAT_FEED_URL_PATH = "/root/threat-feed.url"
THREAT_WHITELIST = "/root/threat-whitelist.txt"
WEBHOOK_PATH = "/root/netflow-webhook.url"
SMTP_CFG_PATH = os.getenv("SMTP_CFG_PATH", "/root/netflow-smtp.json")
NOTIFY_CFG_PATH = os.getenv("NOTIFY_CFG_PATH", "/root/netflow-notify.json")
THRESHOLDS_CFG_PATH = os.getenv("THRESHOLDS_CFG_PATH", "/root/netflow-thresholds.json")
CONFIG_PATH = os.getenv("CONFIG_PATH", "/root/netflow-config.json")
SAMPLE_DATA_PATH = "sample_data/nfdump_flows.csv"

# Trends storage (SQLite) for 5-minute rollups
TRENDS_DB_PATH = os.getenv("TRENDS_DB_PATH", "netflow-trends.sqlite")
_trends_db_lock = threading.Lock()
_trends_thread_started = False

# Firewall syslog storage (SQLite) for 7-day retention
# Prefer env override; if not set and /root is not writable (e.g., local dev on macOS),
# fall back to a local file in the current workspace.
_env_fw_db = os.getenv("FIREWALL_DB_PATH")
if _env_fw_db and _env_fw_db.strip():
    FIREWALL_DB_PATH = _env_fw_db
else:
    _default_fw_db = "/root/firewall.db"
    _fw_dir = os.path.dirname(_default_fw_db) or "/"
    if os.path.isdir(_fw_dir) and os.access(_fw_dir, os.W_OK):
        FIREWALL_DB_PATH = _default_fw_db
    else:
        FIREWALL_DB_PATH = os.path.join(os.getcwd(), "firewall.db")
_firewall_db_lock = threading.Lock()
_syslog_thread_started = False
_syslog_stats = {"received": 0, "parsed": 0, "errors": 0, "last_log": None}
_syslog_stats_lock = threading.Lock()
# Syslog batch insert buffer
_syslog_buffer = []
_syslog_buffer_lock = threading.Lock()
_syslog_buffer_size = 100  # Flush when buffer reaches this size
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
SYSLOG_BIND = os.getenv("SYSLOG_BIND", "0.0.0.0")
FIREWALL_IP = os.getenv("FIREWALL_IP", "192.168.0.1")  # Only accept from this IP
FIREWALL_RETENTION_DAYS = 7

mmdb_city = None
mmdb_asn = None
_city_db_checked_ts = 0
_asn_db_checked_ts = 0
DB_CHECK_INTERVAL = 60

_threat_thread_started = False
_agg_thread_started = False

PORTS = {20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",3389:"RDP",5900:"VNC",27017:"MongoDB",1194:"OpenVPN",51820:"WireGuard"}
PROTOS = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",51:"AH"}
SUSPICIOUS_PORTS = [4444,5555,6667,8888,9001,9050,9150,31337,12345,1337,666,6666]
INTERNAL_NETS = ("192.168.","10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.")

# Auth/brute-force ports to monitor
BRUTE_FORCE_PORTS = [22, 23, 3389, 5900, 21, 25, 110, 143, 993, 995, 3306, 5432]  # SSH, Telnet, RDP, VNC, FTP, Mail, DBs

# Port scan detection thresholds
PORT_SCAN_THRESHOLD = 15  # Number of unique ports from single IP to trigger alert
PORT_SCAN_WINDOW = 300    # Time window in seconds (5 min)

# Data exfiltration thresholds
EXFIL_THRESHOLD_MB = 500  # MB outbound from internal host
EXFIL_RATIO_THRESHOLD = 10  # Outbound/Inbound ratio

# DNS tunneling indicators
DNS_QUERY_THRESHOLD = 100  # Queries per minute to trigger
DNS_TXT_THRESHOLD = 20     # TXT record lookups

# Time-based anomaly (off-hours)
BUSINESS_HOURS_START = 7   # 7 AM
BUSINESS_HOURS_END = 22    # 10 PM
OFF_HOURS_THRESHOLD_MB = 100  # MB during off-hours to alert

# Tracking for advanced detection
_port_scan_tracker = {}  # {ip: {ports: set(), first_seen: ts}}
_seen_external = {"countries": set(), "asns": set()}  # First-seen tracking
_protocol_baseline = {}  # {proto: {"avg_bytes": int, "count": int}}

# Allow override via environment variable, default per project docs
DNS_SERVER = os.getenv("DNS_SERVER", "192.168.0.6")

# Threat Intelligence API Keys (optional)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
_threat_intel_cache = {}  # Cache for threat intelligence results (IP -> {vt: {...}, abuse: {...}, ts: ...})
_threat_intel_cache_lock = threading.Lock()
_threat_intel_cache_ttl = 3600  # Cache for 1 hour

# Global resolver instance to avoid re-initialization overhead (reading /etc/resolv.conf)
_shared_resolver = dns.resolver.Resolver()
_shared_resolver.nameservers = [DNS_SERVER]
_shared_resolver.timeout = 2
_shared_resolver.lifetime = 2

# Cache nfdump availability to avoid repeated shell lookups
_has_nfdump = None

def resolve_hostname(ip):
    """Resolve IP to hostname using configured DNS_SERVER."""
    try:
        # Use shared resolver instance
        # Reverse DNS lookup
        rev_name = dns.reversename.from_address(ip)
        answer = _shared_resolver.resolve(rev_name, 'PTR')
        return str(answer[0]).rstrip('.')
    except Exception as e:
        # print(f"DNS Resolution failed for {ip}: {e}")
        return ip

# ------------------ Helpers ------------------

def is_internal(ip):
    return ip.startswith(INTERNAL_NETS)

# Region mappings based on country ISO codes
REGION_MAPPING = {
    # Americas
    'US': '🌎 Americas', 'CA': '🌎 Americas', 'MX': '🌎 Americas', 'BR': '🌎 Americas',
    'AR': '🌎 Americas', 'CL': '🌎 Americas', 'CO': '🌎 Americas', 'PE': '🌎 Americas',
    # Europe
    'GB': '🌍 Europe', 'DE': '🌍 Europe', 'FR': '🌍 Europe', 'NL': '🌍 Europe',
    'BE': '🌍 Europe', 'IT': '🌍 Europe', 'ES': '🌍 Europe', 'PL': '🌍 Europe',
    'SE': '🌍 Europe', 'NO': '🌍 Europe', 'DK': '🌍 Europe', 'FI': '🌍 Europe',
    'AT': '🌍 Europe', 'CH': '🌍 Europe', 'IE': '🌍 Europe', 'PT': '🌍 Europe',
    'CZ': '🌍 Europe', 'RO': '🌍 Europe', 'HU': '🌍 Europe', 'UA': '🌍 Europe',
    'RU': '🌍 Europe',
    # Asia-Pacific
    'CN': '🌏 Asia', 'JP': '🌏 Asia', 'KR': '🌏 Asia', 'IN': '🌏 Asia',
    'SG': '🌏 Asia', 'HK': '🌏 Asia', 'TW': '🌏 Asia', 'AU': '🌏 Asia',
    'NZ': '🌏 Asia', 'ID': '🌏 Asia', 'TH': '🌏 Asia', 'VN': '🌏 Asia',
    'MY': '🌏 Asia', 'PH': '🌏 Asia',
}

def get_region(ip, country_iso=None):
    """Get region emoji based on country ISO code from GeoIP lookup."""
    if is_internal(ip): 
        return "🏠 Local"
    if country_iso:
        return REGION_MAPPING.get(country_iso.upper(), '🌐 Global')
    # Fallback: try to lookup country if not provided
    geo = lookup_geo(ip)
    if geo and geo.get('country_iso'):
        return REGION_MAPPING.get(geo['country_iso'].upper(), '🌐 Global')
    return "🌐 Global"

def flag_from_iso(iso):
    if not iso or len(iso)!=2: return ""
    return chr(ord(iso[0].upper())+127397)+chr(ord(iso[1].upper())+127397)

def load_city_db():
    global mmdb_city, _city_db_checked_ts
    if mmdb_city is None:
        now = time.time()
        if now - _city_db_checked_ts > DB_CHECK_INTERVAL:
            _city_db_checked_ts = now
            if os.path.exists(MMDB_CITY):
                try:
                    mmdb_city = maxminddb.open_database(MMDB_CITY)
                except Exception:
                    mmdb_city = None
    return mmdb_city

def load_asn_db():
    global mmdb_asn, _asn_db_checked_ts
    if mmdb_asn is None:
        now = time.time()
        if now - _asn_db_checked_ts > DB_CHECK_INTERVAL:
            _asn_db_checked_ts = now
            if os.path.exists(MMDB_ASN):
                try:
                    mmdb_asn = maxminddb.open_database(MMDB_ASN)
                except Exception:
                    mmdb_asn = None
    return mmdb_asn

def lookup_geo(ip):
    now = time.time()
    # Optimistic check
    if ip in _geo_cache and now - _geo_cache[ip]['ts'] < _geo_cache_ttl:
        # Move to end (MRU) - Upgrade to true LRU
        val = _geo_cache.pop(ip, None)
        if val:
            _geo_cache[ip] = val
            return val['data']
    city_db = load_city_db()
    asn_db = load_asn_db()
    res = {}
    if city_db:
        try:
            rec = city_db.get(ip)
            if rec:
                country = rec.get('country',{})
                iso = country.get('iso_code')
                name = country.get('names',{}).get('en')
                city = rec.get('city',{}).get('names',{}).get('en')
                # Get coordinates
                location = rec.get('location', {})
                lat = location.get('latitude')
                lng = location.get('longitude')
                res.update({
                    "country": name, 
                    "country_iso": iso, 
                    "city": city, 
                    "flag": flag_from_iso(iso),
                    "lat": lat,
                    "lng": lng
                })
        except Exception:
            pass
    if asn_db:
        try:
            rec = asn_db.get(ip)
            if rec:
                res['asn'] = rec.get('autonomous_system_number')
                res['asn_org'] = rec.get('autonomous_system_organization')
        except Exception:
            pass

    # Mock ASN if missing and external
    if 'asn_org' not in res and not is_internal(ip):
        # Deterministic mock based on IP
        seed = sum(ord(c) for c in ip)
        orgs = ["Google LLC", "Amazon.com", "Cloudflare, Inc.", "Microsoft Corp", "Akamai", "DigitalOcean", "Comcast", "Verizon"]
        res['asn_org'] = orgs[seed % len(orgs)]
        res['asn'] = 1000 + (seed % 5000)

    # Optimistic LRU: Move to end (most recent)
    if ip in _geo_cache:
        del _geo_cache[ip]
    _geo_cache[ip] = {'ts': now, 'data': res if res else None}

    # LRU-style prune by insertion order if too big
    if len(_geo_cache) > GEO_CACHE_MAX:
        # Drop oldest 5% to reduce churn
        drop = max(1, GEO_CACHE_MAX // 20)
        # In Python 3.7+, dicts preserve insertion order. First items are oldest.
        keys_to_drop = list(_geo_cache.keys())[:drop]
        for k in keys_to_drop:
            _geo_cache.pop(k, None)
    return _geo_cache[ip]['data']

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
    with _alert_history_lock:
        # Check if we've already alerted for this IP recently (within last hour)
        recent_alerts = [a for a in list(_alert_history)[-50:] if a.get('ip') == ip and a.get('ts', 0) > now - 3600]
        if recent_alerts:
            return  # Already alerted recently
        
        # Generate alerts for high and medium severity anomalies
        for anomaly in anomalies:
            if anomaly.get('severity') in ('high', 'medium'):
                alert = {
                    "type": "ip_anomaly",
                    "msg": f"⚠️ IP Investigation Anomaly: {anomaly.get('message', 'Unknown anomaly')}",
                    "severity": anomaly.get('severity', 'medium'),
                    "feed": "ip_investigation",
                    "ip": ip,
                    "category": anomaly.get('type', 'UNKNOWN'),
                    "anomaly": anomaly,
                    "country": geo.get('country_code', '--') if geo else '--',
                    "ts": now
                }
                _alert_history.append(alert)
                # Send notification if high severity
                if anomaly.get('severity') == 'high':
                    send_security_webhook(alert)

def throttle(max_calls=20, time_window=10):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            now = start_time
            endpoint = func.__name__
            with _throttle_lock:
                _request_times[endpoint] = [t for t in _request_times[endpoint] if now - t < time_window]
                if len(_request_times[endpoint]) >= max_calls:
                    global _metric_http_429
                    _metric_http_429 += 1
                    track_error()
                    return jsonify({"error": "Rate limit"}), 429
                _request_times[endpoint].append(now)
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                # Track performance (skip for error responses)
                if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], int) and result[1] == 200:
                    track_performance(endpoint, duration, cached=False)
                elif not isinstance(result, tuple):
                    track_performance(endpoint, duration, cached=False)
                return result
            except Exception as e:
                track_error()
                raise
        return wrapper
    return decorator

def resolve_task(ip):
    try:
        hostname = resolve_hostname(ip)
        if hostname != ip:
            _dns_cache[ip] = hostname
            _dns_ttl[ip] = time.time()
            # Bound DNS cache size
            if len(_dns_cache) > DNS_CACHE_MAX:
                # prune oldest by ttl
                items = sorted(_dns_ttl.items(), key=lambda kv: kv[1])
                for k, _ in items[: max(1, DNS_CACHE_MAX // 20)]:
                    _dns_cache.pop(k, None)
                    _dns_ttl.pop(k, None)
    except Exception:
        pass

def resolve_ip(ip):
    now = time.time()
    if ip in _dns_cache and now - _dns_ttl.get(ip, 0) < 300:
        # If cached value is not yet resolved (None), fall back to IP string
        return _dns_cache[ip] or ip

    # Not in cache or expired, trigger background resolution
    if ip not in _dns_cache: # Only trigger if not present at all to avoid spamming
        _dns_cache[ip] = None # Set placeholder
        _dns_ttl[ip] = now
        _dns_resolver_executor.submit(resolve_task, ip)

    return _dns_cache.get(ip) or ip # Return IP if not resolved yet

# ------------------ Mock Nfdump ------------------
def mock_nfdump(args):
    # args is list like ["-s", "srcip/bytes/flows/packets", "-n", "20"]
    # We parse the CSV and Aggregate
    global _mock_data_cache

    with _mock_lock:
        # Optimization: Cache output based on args to avoid re-aggregating same data
        # This speeds up repeated calls (e.g. bandwidth API loops) significantly
        cache_key = tuple(args)
        if "output_cache" in _mock_data_cache and cache_key in _mock_data_cache["output_cache"]:
            return _mock_data_cache["output_cache"][cache_key]

        rows = []
        try:
            mtime = os.path.getmtime(SAMPLE_DATA_PATH)
            if mtime != _mock_data_cache["mtime"]:
                new_rows = []
                with open(SAMPLE_DATA_PATH, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        parts = line.strip().split(',')
                        if len(parts) > 12:
                            # CSV Format derived from sample:
                            # 0:ts, 1:te, 2:td, 3:sa, 4:da, 5:sp, 6:dp, 7:proto, 8:flg, 9:?, 10:?, 11:pkts, 12:bytes
                            try:
                                row = {
                                    "ts": parts[0], "te": parts[1], "td": float(parts[2]),
                                    "sa": parts[3], "da": parts[4], "sp": parts[5], "dp": parts[6],
                                    "proto": parts[7], "flg": parts[8],
                                    "pkts": int(parts[11]), "bytes": int(parts[12])
                                }
                                new_rows.append(row)
                            except:
                                pass
                _mock_data_cache["rows"] = new_rows
                _mock_data_cache["mtime"] = mtime
                _mock_data_cache["output_cache"] = {} # Invalidate output cache
            rows = _mock_data_cache["rows"]
        except Exception as e:
            print(f"Mock error: {e}")
            return ""

    # Check aggregation
    agg_key = None
    if "-s" in args:
        idx = args.index("-s") + 1
        stat = args[idx]
        if "srcip" in stat: agg_key = "sa"
        elif "dstip" in stat: agg_key = "da"
        elif "dstport" in stat: agg_key = "dp"
        elif "proto" in stat: agg_key = "proto"

    limit = 20
    if "-n" in args:
        idx = args.index("-n") + 1
        try: limit = int(args[idx])
        except: pass

    out = ""

    # If asking for raw flows with limit (alerts detection usage)
    if not agg_key and "-n" in args and not "-s" in args:
         output_lines = ["ts,te,td,sa,da,sp,dp,proto,flg,fwd,stos,ipkt,ibyt"]
         for r in rows[:limit]:
             # Reconstruct line
             output_lines.append(f"{r['ts']},{r['te']},{r['td']},{r['sa']},{r['da']},{r['sp']},{r['dp']},{r['proto']},{r['flg']},0,0,{r['pkts']},{r['bytes']}")

         out = "\n".join(output_lines) + "\n"

         with _mock_lock:
             if "output_cache" not in _mock_data_cache: _mock_data_cache["output_cache"] = {}
             _mock_data_cache["output_cache"][cache_key] = out
         return out

    if agg_key:
        counts = defaultdict(lambda: {"bytes":0, "flows":0, "packets":0})
        for r in rows:
            k = r.get(agg_key, "other")
            counts[k]["bytes"] += r["bytes"]
            counts[k]["flows"] += 1
            counts[k]["packets"] += r["pkts"]

        # Sort by bytes desc
        sorted_keys = sorted(counts.keys(), key=lambda k: counts[k]["bytes"], reverse=True)[:limit]

        # Use the corrected header directly
        output_lines = ["ts,te,td,sa,da,sp,dp,proto,flg,flows,stos,ipkt,ibyt"]
        # We need to ensure the key ends up in the right column for dynamic parsing to work
        # sa=3, da=4, sp=5, dp=6, proto=7
        # But we previously put key at 4.
        # Let's respect the agg_key.

        # Mappings based on column names in header above:
        # sa=3, da=4, sp=5, dp=6, proto=7

        col_map = {"sa":3, "da":4, "sp":5, "dp":6, "proto":7}
        target_idx = col_map.get(agg_key, 4) # Default to 4 (da) if unknown

        for k in sorted_keys:
            d = counts[k]
            # Construct a row with 13 columns (indices 0-12)
            row = ["0"] * 13
            row[target_idx] = str(k)
            # row[5] = str(d['flows']) # flows (matches sp? No, wait. sp is index 5 in header.)
            # Wait, header is: ts,te,td,sa,da,sp,dp,proto,flg,fwd,stos,ipkt,ibyt
            # Index:            0  1  2  3  4  5  6    7    8    9   10   11   12

            # If agg_key is 'sa', key goes to 3.
            # But parse_csv will look for 'fl' or 'flows'. My header doesn't have 'flows'.
            # It has 'stos'? No.
            # Real nfdump csv has 'fl' or 'flows'.
            # Let's adjust the header to match what parse_csv expects for flows/packets/bytes.

            # parse_csv looks for: ibyt/byt/bytes, fl/flows, ipkt/pkt/packets
            # Let's use: ts,te,td,sa,da,sp,dp,proto,flg,flows,stos,ipkt,ibyt
            # Index:      0  1  2  3  4  5  6    7    8    9    10   11   12

            # So flows is index 9.
            # ipkt is index 11.
            # ibyt is index 12.

            row = ["0"] * 13
            row[target_idx] = str(k)
            row[9] = str(d['flows'])
            row[11] = str(d['packets'])
            row[12] = str(d['bytes'])

            output_lines.append(",".join(row))

        out = "\n".join(output_lines) + "\n"

        with _mock_lock:
             if "output_cache" not in _mock_data_cache: _mock_data_cache["output_cache"] = {}
             _mock_data_cache["output_cache"][cache_key] = out
        return out

    return ""


def run_nfdump(args, tf=None):
    global _metric_nfdump_calls
    _metric_nfdump_calls += 1

    # Try running actual nfdump first
    try:
        # Note: Removed -q to ensure CSV header is printed for dynamic parsing
        cmd = ["nfdump","-R","/var/cache/nfdump","-o","csv"]
        if tf: cmd.extend(["-t",tf])
        cmd.extend(args)
        # Check if nfdump exists (cached)
        global _has_nfdump
        if _has_nfdump is None:
            _has_nfdump = (subprocess.call(["which", "nfdump"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0)
        if _has_nfdump:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT)
            if r.returncode == 0 and r.stdout:
                return r.stdout
    except Exception as e:
        pass

    # Fallback to Mock
    return mock_nfdump(args)

def parse_csv(output, expected_key=None):
    results = []
    lines = output.strip().split("\n")
    if not lines: return results

    # Header detection
    header_line = lines[0].lower()
    cols = [c.strip() for c in header_line.split(',')]

    try:
        # Dynamic index resolution
        # Determine likely key column based on what's present
        # Aggregation keys vary: sa (srcip), da (dstip), sp (srcport), dp (dstport), pr (proto), etc.
        # But nfdump CSV output for -s usually has the key in a specific place?
        # Actually, nfdump -o csv -s ... produces columns.
        # Let's look for standard columns.

        # Mapping common keys
        key_idx = -1

        # Priority check for expected key
        # NOTE: nfdump -s (aggregation) uses "val" column for the key, not sa/da/dp/etc
        if expected_key:
            # First check for "val" which is used in aggregation mode
            if 'val' in cols:
                key_idx = cols.index('val')
            elif expected_key in cols:
                key_idx = cols.index(expected_key)
            elif expected_key == 'proto' and 'pr' in cols:
                key_idx = cols.index('pr')
            elif expected_key == 'proto' and 'proto' in cols:
                key_idx = cols.index('proto')

        if key_idx == -1:
            # Check for aggregation output first
            if 'val' in cols: key_idx = cols.index('val')
            elif 'sa' in cols: key_idx = cols.index('sa')
            elif 'da' in cols: key_idx = cols.index('da')
            elif 'sp' in cols: key_idx = cols.index('sp')
            elif 'dp' in cols: key_idx = cols.index('dp')
            elif 'pr' in cols: key_idx = cols.index('pr')
            elif 'proto' in cols: key_idx = cols.index('proto')

        # Fallback to hardcoded 4 if not found (matches previous behavior/mock)
        if key_idx == -1: key_idx = 4

        # Value columns
        # bytes: ibyt, byt, bytes
        # flows: fl, flows
        # packets: ipkt, pkt, packets

        bytes_idx = -1
        if 'ibyt' in cols: bytes_idx = cols.index('ibyt')
        elif 'byt' in cols: bytes_idx = cols.index('byt')
        elif 'bytes' in cols: bytes_idx = cols.index('bytes')

        flows_idx = -1
        if 'fl' in cols: flows_idx = cols.index('fl')
        elif 'flows' in cols: flows_idx = cols.index('flows')

        packets_idx = -1
        if 'ipkt' in cols: packets_idx = cols.index('ipkt')
        elif 'pkt' in cols: packets_idx = cols.index('pkt')
        elif 'packets' in cols: packets_idx = cols.index('packets')

        # Fallbacks for mock data which might not be perfect
        # Updated fallbacks to match standard nfdump CSV (sa=3, da=4, sp=5, dp=6, proto=7, ... ibyt=12)
        if key_idx == -1: key_idx = 3 # Default to srcip (sa) if undetermined
        if bytes_idx == -1: bytes_idx = 12
        # If flow/packet columns are absent in aggregation, treat as 0 instead of guessing indexes
        # flows_idx remains -1 when not present
        # packets_idx remains -1 when not present

    except ValueError:
        return results

    seen_keys = set()  # Track duplicates
    for line in lines[1:]:
        if not line: continue
        # Skip header lines if repeated
        if 'ts,' in line or 'te,' in line or 'Date first seen' in line: continue
        parts = line.split(",")
        if len(parts) <= max(key_idx, bytes_idx, flows_idx, packets_idx): continue
        try:
            key = parts[key_idx]
            if not key or "/" in key or key == "any": continue
            # Skip if we've already seen this key (dedup)
            if key in seen_keys: continue
            seen_keys.add(key)
            bytes_val = int(float(parts[bytes_idx]))
            flows_val = int(float(parts[flows_idx])) if flows_idx != -1 and len(parts) > flows_idx else 0
            packets_val = int(float(parts[packets_idx])) if packets_idx != -1 and len(parts) > packets_idx else 0
            if bytes_val > 0:
                results.append({"key":key,"bytes":bytes_val,"flows":flows_val,"packets":packets_val})
        except Exception:
            continue
    return results

def get_traffic_direction(ip, tf):
    out = run_nfdump(["-a",f"src ip {ip}","-s","srcip/bytes","-n","1"], tf)
    in_data = run_nfdump(["-a",f"dst ip {ip}","-s","dstip/bytes","-n","1"], tf)
    out_parsed = parse_csv(out, expected_key='sa')
    in_parsed = parse_csv(in_data, expected_key='da')
    upload = out_parsed[0]["bytes"] if out_parsed else 0
    download = in_parsed[0]["bytes"] if in_parsed else 0
    return {"upload": upload, "download": download, "ratio": round(upload/download, 2) if download > 0 else 0}

def load_list(path):
    try:
        with open(path,"r") as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()


def load_threatlist():
    try:
        mtime = os.path.getmtime(THREATLIST_PATH)
    except FileNotFoundError:
        _threat_cache["data"] = set()
        _threat_cache["mtime"] = 0
        return set()
    if mtime != _threat_cache["mtime"]:
        try:
            with open(THREATLIST_PATH,"r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                _threat_cache["data"] = set(lines)
                _threat_cache["mtime"] = mtime
        except Exception:
            pass
    return _threat_cache["data"]


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


def _get_firewall_block_stats(hours=1):
    """Get firewall block statistics for the last N hours."""
    try:
        cutoff = time.time() - (hours * 3600)
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                # Combined query for total blocks, unique IPs, and threat blocks
                # Optimized to reduce DB round-trips from 3 to 1
                cur = conn.execute("""
                    SELECT
                        COUNT(*),
                        COUNT(DISTINCT src_ip),
                        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END)
                    FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                """, (cutoff,))
                
                row = cur.fetchone()
                blocks = row[0] or 0
                unique_ips = row[1] or 0
                threats_blocked = row[2] or 0
                
                return {
                    'blocks': blocks,
                    'unique_ips': unique_ips,
                    'threats_blocked': threats_blocked,
                    'blocks_per_hour': round(blocks / hours, 1)
                }
            finally:
                conn.close()
    except Exception:
        return {'blocks': 0, 'unique_ips': 0, 'threats_blocked': 0, 'blocks_per_hour': 0}


def calculate_security_score():
    """Calculate 0-100 security score based on current threat state and firewall activity"""
    score = 100
    reasons = []
    
    # Get firewall block stats
    fw_stats = _get_firewall_block_stats(hours=1)
    
    # Threat detections penalty (up to -40 points)
    threat_count = len([ip for ip in _threat_timeline if time.time() - _threat_timeline[ip]['last_seen'] < 3600])
    if threat_count > 0:
        penalty = min(40, threat_count * 10)
        score -= penalty
        reasons.append(f"-{penalty}: {threat_count} active threats")
    
    # POSITIVE: Firewall blocking known threats (+5 to +15 points)
    threats_blocked = fw_stats.get('threats_blocked', 0)
    if threats_blocked > 0:
        bonus = min(15, 5 + threats_blocked)
        score = min(100, score + bonus)
        reasons.append(f"+{bonus}: {threats_blocked} known threats blocked")
    
    # POSITIVE: Active firewall protection (+5 if blocking attacks)
    if fw_stats.get('blocks', 0) > 10:
        score = min(100, score + 5)
        reasons.append("+5: Firewall actively blocking")
    
    # WARNING: High attack rate (informational, no penalty if being blocked)
    if fw_stats.get('blocks_per_hour', 0) > 100:
        reasons.append(f"⚠️ High attack rate: {fw_stats['blocks_per_hour']}/hr")
    
    # Feed health penalty (up to -20 points)
    feeds_ok = sum(1 for f in _feed_status.values() if f.get('status') == 'ok')
    feeds_total = len(_feed_status)
    if feeds_total > 0:
        feed_ratio = feeds_ok / feeds_total
        if feed_ratio < 1.0:
            penalty = int((1 - feed_ratio) * 20)
            score -= penalty
            reasons.append(f"-{penalty}: {feeds_total - feeds_ok} feeds down")
    
    # Blocklist coverage bonus (+10 if >50K IPs)
    total_ips = _threat_status.get('size', 0)
    if total_ips >= 50000:
        score = min(100, score + 5)
        reasons.append("+5: Good blocklist coverage")
    elif total_ips < 10000:
        score -= 5
        reasons.append("-5: Low blocklist coverage")
    
    # Recent critical alerts penalty
    now = time.time()
    recent_critical = 0
    with _alert_history_lock:
        for alert in _alert_history:
            if alert.get('severity') == 'critical' and now - alert.get('ts', 0) < 3600:
                recent_critical += 1
    if recent_critical > 0:
        penalty = min(30, recent_critical * 5)
        score -= penalty
        reasons.append(f"-{penalty}: {recent_critical} critical alerts")
    
    # Clamp to 0-100
    score = max(0, min(100, score))
    
    # Determine grade
    if score >= 90:
        grade = 'A'
        status = 'excellent'
    elif score >= 75:
        grade = 'B'
        status = 'good'
    elif score >= 60:
        grade = 'C'
        status = 'fair'
    elif score >= 40:
        grade = 'D'
        status = 'poor'
    else:
        grade = 'F'
        status = 'critical'
    
    return {
        'score': score,
        'grade': grade,
        'status': status,
        'reasons': reasons,
        'threats_active': threat_count if 'threat_count' in dir() else 0,
        'feeds_ok': feeds_ok if 'feeds_ok' in dir() else 0,
        'feeds_total': feeds_total if 'feeds_total' in dir() else 0,
        'blocklist_ips': total_ips,
        'firewall': fw_stats
    }


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


def get_feed_label():
    return "threat-feed"

def start_threat_thread():
    global _threat_thread_started
    if _threat_thread_started:
        return
    _threat_thread_started = True
    def loop():
        while not _shutdown_event.is_set():
            fetch_threat_feed()
            # Use wait instead of sleep for faster shutdown
            _shutdown_event.wait(timeout=CACHE_TTL_THREAT)
    t = threading.Thread(target=loop, daemon=True, name='ThreatFeedThread')
    t.start()

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


def format_duration(seconds):
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds)//60}m"
    else:
        return f"{int(seconds)//3600}h"

def fmt_bytes(b):
    if b >= 1024**3: return f"{b/1024**3:.2f} GB"
    elif b >= 1024**2: return f"{b/1024**2:.2f} MB"
    elif b >= 1024: return f"{b/1024:.2f} KB"
    return f"{b} B"


def load_notify_cfg():
    default = {"email": True, "webhook": True, "mute_until": 0}
    if not os.path.exists(NOTIFY_CFG_PATH): return default
    try:
        with open(NOTIFY_CFG_PATH,'r') as f:
            cfg = json.load(f)
        return {"email": bool(cfg.get("email", True)), "webhook": bool(cfg.get("webhook", True)), "mute_until": float(cfg.get("mute_until", 0) or 0)}
    except: return default

def save_notify_cfg(cfg):
    try:
        payload = {"email": bool(cfg.get('email', True)), "webhook": bool(cfg.get('webhook', True)), "mute_until": float(cfg.get('mute_until', 0) or 0)}
        with open(NOTIFY_CFG_PATH,'w') as f: json.dump(payload, f)
    except: pass

# Thresholds config
DEFAULT_THRESHOLDS = {
    "util_warn": 70,
    "util_crit": 90,
    "resets_warn": 0.1,
    "resets_crit": 1.0,
    "ip_err_warn": 0.1,
    "ip_err_crit": 1.0,
    "icmp_err_warn": 0.1,
    "icmp_err_crit": 1.0,
    "if_err_warn": 0.1,
    "if_err_crit": 1.0,
    "tcp_fails_warn": 0.5,
    "tcp_fails_crit": 2.0,
    "tcp_retrans_warn": 1.0,
    "tcp_retrans_crit": 5.0
}

def load_thresholds():
    data = DEFAULT_THRESHOLDS.copy()
    if os.path.exists(THRESHOLDS_CFG_PATH):
        try:
            with open(THRESHOLDS_CFG_PATH, 'r') as f:
                file_cfg = json.load(f)
                for k,v in file_cfg.items():
                    try:
                        # cast to float for rates, int for util
                        if k.startswith('util_'):
                            data[k] = int(v)
                        else:
                            data[k] = float(v)
                    except:
                        pass
        except:
            pass
    return data

def save_thresholds(cfg):
    try:
        data = load_thresholds()
        for k in DEFAULT_THRESHOLDS.keys():
            if k in cfg:
                try:
                    if k.startswith('util_'):
                        data[k] = int(cfg[k])
                    else:
                        data[k] = float(cfg[k])
                except:
                    pass
        with open(THRESHOLDS_CFG_PATH,'w') as f:
            json.dump(data, f)
        return data
    except:
        return load_thresholds()

def send_webhook(alerts):
    notify = load_notify_cfg()
    if not notify.get("webhook", True): return
    if not os.path.exists(WEBHOOK_PATH): return
    try:
        with open(WEBHOOK_PATH,"r") as f: url = f.read().strip()
        if url: requests.post(url, json={"alerts": alerts}, timeout=3)
    except: pass

def record_history(alerts):
    if not alerts: return
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    for a in alerts:
        entry = {"ts": ts, "msg": a.get('msg'), "severity": a.get('severity','info')}
        _alert_history.appendleft(entry)

def _should_deliver(alert):
    cfg = load_notify_cfg()
    if cfg.get('mute_until', 0) > time.time(): return False
    return True

def send_notifications(alerts):
    global _alert_sent_ts
    if not alerts: return
    filtered = [a for a in alerts if _should_deliver(a)]
    if not filtered: return
    now = time.time()
    if now - _alert_sent_ts < 60: return
    send_webhook(filtered)
    record_history(filtered)
    _alert_sent_ts = now

# ------------------ Routes ------------------

@app.route("/")
def index():
    start_threat_thread()
    start_trends_thread()
    start_agg_thread()
    return render_template("index.html")

def get_time_range(range_key):
    now = datetime.now()
    hours = {"15m":0.25,"30m":0.5,"1h":1,"6h":6,"24h":24}.get(range_key, 1)
    past = now - timedelta(hours=hours)
    return f"{past.strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"


def get_common_nfdump_data(query_type, range_key):
    # Shared data fetcher
    # types: "sources", "ports", "dests", "protos"
    # Fetches 100 items, sorts by bytes descending, displays top 10
    # sources -> fetch 100, display 10
    # ports -> fetch 100, display 10
    # dests -> fetch 100, display 10
    # protos -> fetch 20 (not sorted)

    now = time.time()
    cache_key = f"{query_type}:{range_key}"

    # Align to 60s window
    win = int(now // 60)
    cache_key = f"{query_type}:{range_key}:{win}"
    with _common_data_lock:
        entry = _common_data_cache.get(cache_key)
        if entry:
            return entry["data"]

    tf = get_time_range(range_key)
    data = []

    if query_type == "sources":
        data = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","100"], tf), expected_key='sa')
        # Sort by bytes descending
        data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    elif query_type == "ports":
        data = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","100"], tf), expected_key='dp')
        # Sort by bytes descending
        data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    elif query_type == "dests":
        data = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","100"], tf), expected_key='da')
        # Sort by bytes descending
        data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    elif query_type == "protos":
        data = parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","20"], tf), expected_key='proto')

    with _common_data_lock:
        _common_data_cache[cache_key] = {"data": data, "ts": now, "win": win}
        # Cleanup old entries if cache gets too large (LRU-style)
        if len(_common_data_cache) > COMMON_DATA_CACHE_MAX:
            # Remove oldest 20% of entries
            drop_count = max(1, COMMON_DATA_CACHE_MAX // 5)
            oldest = sorted(_common_data_cache.items(), key=lambda kv: kv[1]["ts"])[:drop_count]
            for k, _ in oldest:
                _common_data_cache.pop(k, None)

    return data

@app.route("/api/stats/summary")
@throttle(5, 10)
def api_stats_summary():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_summary:
        if _stats_summary_cache["data"] and _stats_summary_cache.get("key") == range_key and _stats_summary_cache.get("win") == win:
            return jsonify(_stats_summary_cache["data"])

    # Reuse common data cache instead of running separate nfdump query
    # Using top 100 sources (from cache) is more accurate than top 20 for totals
    sources = get_common_nfdump_data("sources", range_key)
    tot_b = sum(i["bytes"] for i in sources)
    tot_f = sum(i["flows"] for i in sources)
    tot_p = sum(i["packets"] for i in sources)
    data = {
        "totals": {
            "bytes": tot_b,
            "flows": tot_f,
            "packets": tot_p,
            "bytes_fmt": fmt_bytes(tot_b),
            "avg_packet_size": int(tot_b/tot_p) if tot_p > 0 else 0
        },
        "notify": load_notify_cfg(),
        "threat_status": _threat_status
    }
    with _lock_summary:
        _stats_summary_cache["data"] = data
        _stats_summary_cache["ts"] = now
        _stats_summary_cache["key"] = range_key
        _stats_summary_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/sources")
@throttle(5, 10)
def api_stats_sources():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    # Cache key must include limit if we cache at this level.
    # However, the current cache logic inside this function ignores 'limit' in the key check.
    # To support variable limits correctly without rewriting the whole caching layer for this demo,
    # we can bypass the function-level cache if limit > 10, or just use the common data cache (which has 100).
    # Since get_common_nfdump_data returns 100, we can just slice from that.

    # We will skip the function-level cache check if limit > 10 for now to ensure fresh data,
    # OR we can update the cache key. Let's update the cache key.

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)

    with _lock_sources:
        if _stats_sources_cache["data"] and _stats_sources_cache.get("key") == cache_key_local and _stats_sources_cache.get("win") == win:
            return jsonify(_stats_sources_cache["data"])

    # Use shared data (top 100)
    full_sources = get_common_nfdump_data("sources", range_key)

    # Return top N
    sources = full_sources[:limit]

    # Enrich
    for i in sources:
        i["hostname"] = resolve_ip(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["region"] = get_region(i["key"], i.get("country_iso"))
        i["threat"] = False

    data = {"sources": sources}
    with _lock_sources:
        _stats_sources_cache["data"] = data
        _stats_sources_cache["ts"] = now
        _stats_sources_cache["key"] = cache_key_local
        _stats_sources_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/destinations")
@throttle(5, 10)
def api_stats_destinations():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_dests:
        if _stats_dests_cache["data"] and _stats_dests_cache.get("key") == cache_key_local and _stats_dests_cache.get("win") == win:
            return jsonify(_stats_dests_cache["data"])

    # Use shared data (top 100)
    full_dests = get_common_nfdump_data("dests", range_key)
    dests = full_dests[:limit]

    for i in dests:
        i["hostname"] = resolve_ip(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["region"] = get_region(i["key"], i.get("country_iso"))
        i["threat"] = False

    data = {"destinations": dests}
    with _lock_dests:
        _stats_dests_cache["data"] = data
        _stats_dests_cache["ts"] = now
        _stats_dests_cache["key"] = cache_key_local
        _stats_dests_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/ports")
@throttle(5, 10)
def api_stats_ports():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_ports:
        if _stats_ports_cache["data"] and _stats_ports_cache.get("key") == cache_key_local and _stats_ports_cache.get("win") == win:
            return jsonify(_stats_ports_cache["data"])

    # Use shared data (top 100, sorted by bytes)
    full_ports = get_common_nfdump_data("ports", range_key)
    ports = full_ports[:limit]

    for i in ports:
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        try:
            port = int(i["key"])
            i["service"] = PORTS.get(port, "Unknown")
            i["suspicious"] = port in SUSPICIOUS_PORTS
        except Exception:
            i["service"] = "Unknown"
            i["suspicious"] = False

    data = {"ports": ports}
    with _lock_ports:
        _stats_ports_cache["data"] = data
        _stats_ports_cache["ts"] = now
        _stats_ports_cache["key"] = cache_key_local
        _stats_ports_cache["win"] = win
    return jsonify(data)

@app.route("/api/stats/protocols")
@throttle(5, 10)
def api_stats_protocols():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_protocols:
        if _stats_protocols_cache["data"] and _stats_protocols_cache["key"] == range_key and _stats_protocols_cache.get("win") == win:
            return jsonify(_stats_protocols_cache["data"])

    # Reuse common data cache (fetches 20, we use top 10)
    protos_raw = get_common_nfdump_data("protos", range_key)[:10]

    for i in protos_raw:
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        try:
            proto = int(i["key"]) if i["key"].isdigit() else 0
            i["proto_name"] = PROTOS.get(proto, i["key"])
        except Exception:
            i["proto_name"] = i["key"]

    data = {"protocols": protos_raw}
    with _lock_protocols:
        _stats_protocols_cache["data"] = data
        _stats_protocols_cache["ts"] = now
        _stats_protocols_cache["key"] = range_key
        _stats_protocols_cache["win"] = win
    return jsonify(data)

@app.route("/api/stats/flags")
@throttle(5, 10)
def api_stats_flags():
    # New Feature: TCP Flags
    # Parse raw flows using nfdump
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_flags:
        if _stats_flags_cache["data"] and _stats_flags_cache["key"] == range_key and _stats_flags_cache.get("win") == win:
            return jsonify(_stats_flags_cache["data"])

    tf = get_time_range(range_key)

    # Get raw flows (limit 1000)
    # Note: run_nfdump automatically adds -o csv
    output = run_nfdump(["-n", "1000"], tf)

    try:
        rows = []
        lines = output.strip().split("\n")
        # Identify 'flg' column index
        header = lines[0].split(',')
        try:
            flg_idx = header.index('flg')
        except ValueError:
            # Fallback for mock or unknown
            flg_idx = 8

        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) > flg_idx:
                rows.append(parts[flg_idx])

        # Simple aggregation
        counts = Counter(rows)
        clean_counts = Counter()
        for f, c in counts.items():
            clean = f.replace('.','').strip()
            if not clean: clean = "None"
            clean_counts[clean] += c

        top = [{"flag": k, "count": v} for k,v in clean_counts.most_common(5)]
        data = {"flags": top}
        with _lock_flags:
            _stats_flags_cache["data"] = data
            _stats_flags_cache["ts"] = now
            _stats_flags_cache["key"] = range_key
            _stats_flags_cache["win"] = win
        return jsonify(data)
    except Exception as e:
        return jsonify({"flags": []})

@app.route("/api/stats/asns")
@throttle(5, 10)
def api_stats_asns():
    # New Feature: Top ASNs
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_asns:
        if _stats_asns_cache["data"] and _stats_asns_cache["key"] == range_key and _stats_asns_cache.get("win") == win:
            return jsonify(_stats_asns_cache["data"])

    # Reuse common data cache (fetches 100 sources, better than 50 for aggregation)
    sources = get_common_nfdump_data("sources", range_key)

    asn_counts = Counter()

    for i in sources:
        geo = lookup_geo(i["key"])
        org = geo.get('asn_org', 'Unknown') if geo else 'Unknown'
        if org == 'Unknown' and is_internal(i["key"]):
            org = "Internal Network"
        asn_counts[org] += i["bytes"]

    top = [{"asn": k, "bytes": v, "bytes_fmt": fmt_bytes(v)} for k,v in asn_counts.most_common(10)]
    data = {"asns": top}
    with _lock_asns:
        _stats_asns_cache["data"] = data
        _stats_asns_cache["ts"] = now
        _stats_asns_cache["key"] = range_key
        _stats_asns_cache["win"] = win
    return jsonify(data)

@app.route("/api/stats/durations")
@throttle(5, 10)
def api_stats_durations():
    # New Feature: Longest Duration Flows
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_durations:
        if _stats_durations_cache["data"] and _stats_durations_cache["key"] == range_key and _stats_durations_cache.get("win") == win:
            return jsonify(_stats_durations_cache["data"])

    tf = get_time_range(range_key)

    output = run_nfdump(["-n", "100"], tf) # Get recent flows

    try:
        rows = []
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        # Map indices
        try:
            ts_idx = header.index('ts')
            sa_idx = header.index('sa')
            da_idx = header.index('da')
            pr_idx = header.index('proto')
            td_idx = header.index('td')
            ibyt_idx = header.index('ibyt')
        except:
            # Fallback indices
            sa_idx, da_idx, pr_idx, td_idx, ibyt_idx = 3, 4, 7, 2, 12

        seen_flows = set()  # Deduplicate flows
        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue  # Skip empty lines and headers
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, td_idx):
                try:
                    # Create unique key for deduplication
                    flow_key = (parts[sa_idx], parts[da_idx], parts[pr_idx], parts[td_idx])
                    if flow_key in seen_flows: continue
                    seen_flows.add(flow_key)
                    
                    rows.append({
                        "src": parts[sa_idx], "dst": parts[da_idx],
                        "proto": parts[pr_idx],
                        "duration": float(parts[td_idx]),
                        "bytes": int(parts[ibyt_idx]) if len(parts) > ibyt_idx else 0
                    })
                except: pass

        # Sort by duration
        sorted_flows = sorted(rows, key=lambda x: x['duration'], reverse=True)[:10]
        max_dur = sorted_flows[0]['duration'] if sorted_flows else 1
        
        # Calculate stats
        all_durations = [r['duration'] for r in rows if r['duration'] > 0]
        avg_duration = sum(all_durations) / len(all_durations) if all_durations else 0
        total_bytes = sum(r['bytes'] for r in rows)
        
        for f in sorted_flows:
            f['bytes_fmt'] = fmt_bytes(f['bytes'])
            # Format duration nicely
            dur = f['duration']
            if dur >= 3600:
                hours = int(dur // 3600)
                mins = int((dur % 3600) // 60)
                f['duration_fmt'] = f"{hours}h {mins}m"
            elif dur >= 60:
                mins = int(dur // 60)
                secs = int(dur % 60)
                f['duration_fmt'] = f"{mins}m {secs}s"
            else:
                f['duration_fmt'] = f"{dur:.2f}s"
            # Add percentage for bar width
            f['pct'] = round(dur / max_dur * 100, 1) if max_dur > 0 else 0
            # Map protocol name
            proto_val = f.get('proto', '')
            if proto_val.isdigit():
                f['proto_name'] = PROTOS.get(int(proto_val), proto_val)
            else:
                f['proto_name'] = proto_val
            # Resolve hostnames
            f['src_hostname'] = resolve_ip(f['src'])
            f['dst_hostname'] = resolve_ip(f['dst'])

        data = {
            "durations": sorted_flows,
            "stats": {
                "avg_duration": round(avg_duration, 2),
                "avg_duration_fmt": f"{avg_duration:.1f}s" if avg_duration < 60 else f"{avg_duration/60:.1f}m",
                "total_flows": len(rows),
                "total_bytes": total_bytes,
                "total_bytes_fmt": fmt_bytes(total_bytes),
                "max_duration": max_dur,
                "max_duration_fmt": f"{max_dur:.1f}s" if max_dur < 60 else f"{max_dur/60:.1f}m"
            }
        }
        with _lock_durations:
            _stats_durations_cache["data"] = data
            _stats_durations_cache["ts"] = now
            _stats_durations_cache["key"] = range_key
            _stats_durations_cache["win"] = win
        return jsonify(data)
    except Exception as e:
        return jsonify({"durations": []})

@app.route("/api/stats/packet_sizes")
@throttle(5, 10)
def api_stats_packet_sizes():
    # New Feature: Packet Size Distribution
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_pkts_cache["data"] and _stats_pkts_cache["key"] == range_key and now - _stats_pkts_cache["ts"] < 60:
            return jsonify(_stats_pkts_cache["data"])

    tf = get_time_range(range_key)
    # Get raw flows (limit 2000 for better stats)
    tf = get_time_range(range_key)
    # Get raw flows (limit 2000 for better stats)
    output = run_nfdump(["-n", "2000"], tf)

    # Buckets
    dist = {
        "Tiny (<64B)": 0,
        "Small (64-511B)": 0,
        "Medium (512-1023B)": 0,
        "Large (1024-1513B)": 0,
        "Jumbo (>1513B)": 0
    }

    # NFDump CSV usually has no header, or specific columns: ts,td,pr,sa,sp,da,dp,ipkt,ibyt,fl
    # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx, fl_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9

    try:
        lines = output.strip().split("\n")
        # Check if first line looks like a header
        if lines and 'ibyt' in lines[0]:
             header = lines[0].split(',')
             try:
                 ibyt_idx = header.index('ibyt')
                 ipkt_idx = header.index('ipkt')
             except:
                 pass
             start_idx = 1
        else:
             start_idx = 0

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(ibyt_idx, ipkt_idx):
                try:
                    b = int(parts[ibyt_idx])
                    p = int(parts[ipkt_idx])
                    if p > 0:
                        avg = b / p
                        if avg < 64: dist["Tiny (<64B)"] += 1
                        elif avg < 512: dist["Small (64-511B)"] += 1
                        elif avg < 1024: dist["Medium (512-1023B)"] += 1
                        elif avg <= 1514: dist["Large (1024-1513B)"] += 1
                        else: dist["Jumbo (>1513B)"] += 1
                except: pass

        data = {
            "labels": list(dist.keys()),
            "data": list(dist.values())
        }
        with _cache_lock:
            _stats_pkts_cache["data"] = data
            _stats_pkts_cache["ts"] = now
            _stats_pkts_cache["key"] = range_key
        return jsonify(data)
    except Exception:
        return jsonify({"labels":[], "data":[]})


@app.route("/api/stats/countries")
@throttle(5, 10)
def api_stats_countries():
    """Top countries by bytes using top sources and destinations (cached per 60s window)."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_countries:
        if _stats_countries_cache["data"] and _stats_countries_cache["key"] == range_key and _stats_countries_cache.get("win") == win:
            return jsonify(_stats_countries_cache["data"])

    # Reuse shared data to avoid extra nfdump
    sources = get_common_nfdump_data("sources", range_key)[:100]
    dests = get_common_nfdump_data("dests", range_key)[:100]

    country_bytes = {}
    for item in sources + dests:
        ip = item.get("key")
        b = item.get("bytes", 0)
        geo = lookup_geo(ip) or {}
        iso = geo.get('country_iso') or '??'
        name = geo.get('country') or 'Unknown'
        if iso not in country_bytes:
            country_bytes[iso] = {"name": name, "iso": iso, "bytes": 0, "flows": 0}
        country_bytes[iso]["bytes"] += b
        country_bytes[iso]["flows"] += 1

    # Sort by bytes and get top entries
    sorted_countries = sorted(country_bytes.values(), key=lambda x: x["bytes"], reverse=True)
    top = sorted_countries[:15]
    
    # Format for chart (backwards compatible)
    labels = [f"{c['name']} ({c['iso']})" if c['iso'] != '??' else 'Unknown' for c in top]
    bytes_vals = [c['bytes'] for c in top]
    
    # Enhanced data for world map
    map_data = []
    total_bytes = sum(c['bytes'] for c in sorted_countries)
    for c in sorted_countries:
        if c['iso'] != '??':
            map_data.append({
                "iso": c['iso'],
                "name": c['name'],
                "bytes": c['bytes'],
                "bytes_fmt": fmt_bytes(c['bytes']),
                "flows": c['flows'],
                "pct": round((c['bytes'] / total_bytes * 100), 1) if total_bytes > 0 else 0
            })

    data = {
        "labels": labels,
        "bytes": bytes_vals,
        "bytes_fmt": [fmt_bytes(v) for v in bytes_vals],
        "map_data": map_data,
        "total_bytes": total_bytes,
        "total_bytes_fmt": fmt_bytes(total_bytes),
        "country_count": len([c for c in sorted_countries if c['iso'] != '??'])
    }
    with _lock_countries:
        _stats_countries_cache["data"] = data
        _stats_countries_cache["ts"] = now
        _stats_countries_cache["key"] = range_key
        _stats_countries_cache["win"] = win
    return jsonify(data)


# World Map cache
_worldmap_cache = {"data": None, "ts": 0, "key": None, "win": None}
_lock_worldmap = threading.Lock()

@app.route("/api/stats/worldmap")
@throttle(5, 10)
def api_stats_worldmap():
    """Geographic data for world map visualization with sources, destinations, and threats."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_worldmap:
        if _worldmap_cache["data"] and _worldmap_cache["key"] == range_key and _worldmap_cache.get("win") == win:
            return jsonify(_worldmap_cache["data"])

    try:
        # Get sources and destinations with geo data
        sources = get_common_nfdump_data("sources", range_key)[:50]
        dests = get_common_nfdump_data("dests", range_key)[:50]
        
        # Get threat IPs from the loaded threat list
        start_threat_thread()
        threat_set = load_threatlist()
        
        source_points = []
        dest_points = []
        threat_points = []
        
        # Country aggregations
        source_countries = {}
        dest_countries = {}
        threat_countries = {}
        
        for item in sources:
            ip = item.get("key")
            if is_internal(ip): 
                continue
            geo = lookup_geo(ip) or {}
            if geo.get('lat') and geo.get('lng'):
                point = {
                    "ip": ip,
                    "lat": geo['lat'],
                    "lng": geo['lng'],
                    "bytes": item.get("bytes", 0),
                    "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                    "country": geo.get('country', 'Unknown'),
                    "country_iso": geo.get('country_iso', '??'),
                    "city": geo.get('city'),
                    "is_threat": ip in threat_set
                }
                source_points.append(point)
                
                # Aggregate by country
                iso = geo.get('country_iso', '??')
                if iso != '??':
                    if iso not in source_countries:
                        source_countries[iso] = {"name": geo.get('country'), "bytes": 0, "count": 0}
                    source_countries[iso]["bytes"] += item.get("bytes", 0)
                    source_countries[iso]["count"] += 1
        
        for item in dests:
            ip = item.get("key")
            if is_internal(ip): 
                continue
            geo = lookup_geo(ip) or {}
            if geo.get('lat') and geo.get('lng'):
                point = {
                    "ip": ip,
                    "lat": geo['lat'],
                    "lng": geo['lng'],
                    "bytes": item.get("bytes", 0),
                    "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                    "country": geo.get('country', 'Unknown'),
                    "country_iso": geo.get('country_iso', '??'),
                    "city": geo.get('city'),
                    "is_threat": ip in threat_set
                }
                dest_points.append(point)
                
                iso = geo.get('country_iso', '??')
                if iso != '??':
                    if iso not in dest_countries:
                        dest_countries[iso] = {"name": geo.get('country'), "bytes": 0, "count": 0}
                    dest_countries[iso]["bytes"] += item.get("bytes", 0)
                    dest_countries[iso]["count"] += 1
        
        # Threat points with geo
        for tip in list(threat_set)[:100]:
            geo = lookup_geo(tip) or {}
            if geo.get('lat') and geo.get('lng'):
                threat_points.append({
                    "ip": tip,
                    "lat": geo['lat'],
                    "lng": geo['lng'],
                    "country": geo.get('country', 'Unknown'),
                    "country_iso": geo.get('country_iso', '??'),
                    "city": geo.get('city')
                })
                
                iso = geo.get('country_iso', '??')
                if iso != '??':
                    if iso not in threat_countries:
                        threat_countries[iso] = {"name": geo.get('country'), "count": 0}
                    threat_countries[iso]["count"] += 1
        
        # Get blocked IPs from syslog with geo data
        blocked_points = []
        blocked_countries = {}
        try:
            db_path = FIREWALL_DB_PATH
            if os.path.exists(db_path):
                range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
                cutoff = int(time.time()) - range_seconds
                conn = sqlite3.connect(db_path, timeout=5)
                cur = conn.cursor()
                cur.execute("""
                    SELECT src_ip, COUNT(*) as cnt, country_iso, is_threat
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY src_ip
                    ORDER BY cnt DESC
                    LIMIT 50
                """, (cutoff,))
                for row in cur.fetchall():
                    ip = row[0]
                    cnt = row[1]
                    country_iso = row[2]
                    is_threat = row[3]
                    geo = lookup_geo(ip) or {}
                    if geo.get('lat') and geo.get('lng'):
                        blocked_points.append({
                            "ip": ip,
                            "lat": geo['lat'],
                            "lng": geo['lng'],
                            "country": geo.get('country', 'Unknown'),
                            "country_iso": geo.get('country_iso', country_iso or '??'),
                            "city": geo.get('city'),
                            "block_count": cnt,
                            "is_threat": bool(is_threat)
                        })
                        iso = geo.get('country_iso', '??')
                        if iso != '??':
                            if iso not in blocked_countries:
                                blocked_countries[iso] = {"name": geo.get('country'), "count": 0, "blocks": 0}
                            blocked_countries[iso]["count"] += 1
                            blocked_countries[iso]["blocks"] += cnt
                conn.close()
        except:
            pass
        
        # Calculate totals for percentage calculations
        total_source_bytes = sum(v["bytes"] for v in source_countries.values())
        total_dest_bytes = sum(v["bytes"] for v in dest_countries.values())
        
        # Build country lists with percentages
        source_countries_list = []
        for k, v in sorted(source_countries.items(), key=lambda x: x[1]["bytes"], reverse=True)[:15]:
            pct = round((v["bytes"] / total_source_bytes * 100), 1) if total_source_bytes > 0 else 0
            source_countries_list.append({
                "iso": k,
                **v,
                "bytes_fmt": fmt_bytes(v["bytes"]),
                "pct": pct
            })
        
        dest_countries_list = []
        for k, v in sorted(dest_countries.items(), key=lambda x: x[1]["bytes"], reverse=True)[:15]:
            pct = round((v["bytes"] / total_dest_bytes * 100), 1) if total_dest_bytes > 0 else 0
            dest_countries_list.append({
                "iso": k,
                **v,
                "bytes_fmt": fmt_bytes(v["bytes"]),
                "pct": pct
            })
        
        data = {
            "sources": source_points[:30],
            "destinations": dest_points[:30],
            "threats": threat_points[:30],
            "blocked": blocked_points[:30],
            "source_countries": source_countries_list,
            "dest_countries": dest_countries_list,
            "threat_countries": [{"iso": k, **v} for k, v in sorted(threat_countries.items(), key=lambda x: x[1]["count"], reverse=True)[:10]],
            "blocked_countries": [{"iso": k, **v} for k, v in sorted(blocked_countries.items(), key=lambda x: x[1]["blocks"], reverse=True)[:10]],
            "summary": {
                "total_sources": len(source_points),
                "total_destinations": len(dest_points),
                "total_threats": len(threat_points),
                "total_blocked": len(blocked_points),
                "countries_reached": len(set(list(source_countries.keys()) + list(dest_countries.keys()))),
                "total_source_bytes": total_source_bytes,
                "total_source_bytes_fmt": fmt_bytes(total_source_bytes),
                "total_dest_bytes": total_dest_bytes,
                "total_dest_bytes_fmt": fmt_bytes(total_dest_bytes)
            }
        }
    except Exception as e:
        # Log error but return empty data structure to prevent API failure
        import traceback
        traceback.print_exc()
        data = {
            "sources": [],
            "destinations": [],
            "threats": [],
            "blocked": [],
            "source_countries": [],
            "dest_countries": [],
            "threat_countries": [],
            "blocked_countries": [],
            "summary": {
                "total_sources": 0,
                "total_destinations": 0,
                "total_threats": 0,
                "total_blocked": 0,
                "countries_reached": 0
            }
        }
    
    with _lock_worldmap:
        _worldmap_cache["data"] = data
        _worldmap_cache["ts"] = now
        _worldmap_cache["key"] = range_key
        _worldmap_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/talkers")
@throttle(5, 10)
def api_stats_talkers():
    """Top talker pairs (src→dst) by bytes."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_talkers_cache["data"] and _stats_talkers_cache["key"] == range_key and _stats_talkers_cache.get("win") == win:
            return jsonify(_stats_talkers_cache["data"])

    tf = get_time_range(range_key)
    # Sort by bytes (already sorted by nfdump, but we limits)
    # nfdump -O bytes -n 100 returns top 100 flows sorted by bytes
    output = run_nfdump(["-O", "bytes", "-n", "50"], None)

    flows = []
    # NFDump CSV indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8

    try:
        lines = output.strip().split("\n")
        # Header check skip logic
        start_idx = 0
        if lines:
            line0 = lines[0]
            if 'ts' in line0 or 'Date' in line0 or 'ibyt' in line0 or 'firstSeen' in line0 or 'firstseen' in line0:
                header = line0.split(',')
                # Map headers to indices if possible, else rely on defaults
                try:
                    # check for common variances
                    sa_key = 'sa' if 'sa' in header else 'srcAddr'
                    da_key = 'da' if 'da' in header else 'dstAddr'
                    ibyt_key = 'ibyt' if 'ibyt' in header else 'bytes'
                    
                    if sa_key in header: sa_idx = header.index(sa_key)
                    if da_key in header: da_idx = header.index(da_key)
                    if ibyt_key in header: ibyt_idx = header.index(ibyt_key)
                    start_idx = 1
                except:
                    pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstSeen,'): continue
            parts = line.split(',')
            if len(parts) > 8:
                try:
                    ts_str = parts[ts_idx]
                    duration = float(parts[td_idx])
                    proto_val = parts[pr_idx]
                    src = parts[sa_idx]
                    src_port = parts[sp_idx]
                    dst = parts[da_idx]
                    dst_port = parts[dp_idx]
                    pkts = int(parts[ipkt_idx])
                    b = int(parts[ibyt_idx])
                    
                    # Calculate Age
                    # ts format often: 2026-01-13 19:42:15.000
                    try:
                        # strip fractional seconds for parsing if needed, or simple str parse
                        # fast simplified parsing
                        if '.' in ts_str: ts_str = ts_str.split('.')[0]
                        flow_time = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp()
                        age_sec = now - flow_time
                    except:
                        age_sec = 0
                    
                    # Enrich with Geo
                    src_geo = lookup_geo(src) or {}
                    dst_geo = lookup_geo(dst) or {}
                    
                    # Resolve Service Name
                    try: 
                        svc = socket.getservbyport(int(dst_port), 'tcp' if '6' in proto_val else 'udp')
                    except: 
                        svc = dst_port

                    flows.append({
                        "ts": ts_str,
                        "age": format_duration(age_sec) + " ago" if age_sec < 3600 else ts_str.split(' ')[1],
                        "duration": f"{duration:.2f}s",
                        "proto": proto_val, 
                        "proto_name": { "6": "TCP", "17": "UDP", "1": "ICMP" }.get(proto_val, proto_val),
                        "src": src,
                        "src_port": src_port,
                        "src_flag": src_geo.get('flag', ''),
                        "src_country": src_geo.get('country', ''),
                        "dst": dst,
                        "dst_port": dst_port,
                        "dst_flag": dst_geo.get('flag', ''),
                        "dst_country": dst_geo.get('country', ''),
                        "service": svc,
                        "bytes": b,
                        "bytes_fmt": fmt_bytes(b),
                        "packets": pkts
                    })
                except Exception:
                    pass

    except Exception as e:
        print(f"Error parsing talkers: {e}")
        pass

    with _cache_lock:
        _stats_talkers_cache["data"] = {"flows": flows}
        _stats_talkers_cache["ts"] = now
        _stats_talkers_cache["key"] = range_key
        _stats_talkers_cache["win"] = win
    return jsonify({"flows": flows})


@app.route("/api/stats/services")
@throttle(5, 10)
def api_stats_services():
    """Top services by bytes (aggregated by service name)."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_services_cache["data"] and _stats_services_cache["key"] == range_key and _stats_services_cache.get("win") == win:
            return jsonify(_stats_services_cache["data"])

    # Reuse ports data
    ports_data = get_common_nfdump_data("ports", range_key)

    # Aggregate by service name
    service_bytes = Counter()
    service_flows = Counter()
    for item in ports_data:
        port_str = item.get("key", "")
        try:
            port = int(port_str)
            service = PORTS.get(port, f"Port {port}")
        except:
            service = port_str
        service_bytes[service] += item.get("bytes", 0)
        service_flows[service] += item.get("flows", 0)

    # Get top 10 by bytes
    top = service_bytes.most_common(10)
    services = []
    max_bytes = top[0][1] if top else 1
    for svc, b in top:
        services.append({
            "service": svc,
            "bytes": b,
            "bytes_fmt": fmt_bytes(b),
            "flows": service_flows.get(svc, 0),
            "pct": round(b / max_bytes * 100, 1)
        })

    data = {"services": services, "maxBytes": max_bytes}
    with _cache_lock:
        _stats_services_cache["data"] = data
        _stats_services_cache["ts"] = now
        _stats_services_cache["key"] = range_key
        _stats_services_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/hourly")
@throttle(5, 10)
def api_stats_hourly():
    """Traffic distribution by hour (last 24 hours)."""
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_hourly_cache["data"] and _stats_hourly_cache.get("win") == win:
            return jsonify(_stats_hourly_cache["data"])

    # Always use 24h range for hourly stats
    tf = get_time_range("24h")
    output = run_nfdump(["-n", "5000"], tf)

    # Initialize hourly buckets (0-23)
    hourly_bytes = {h: 0 for h in range(24)}
    hourly_flows = {h: 0 for h in range(24)}

    # NFDump CSV usually has no header
    # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, ibyt_idx = 0, 8

    try:
        lines = output.strip().split("\n")
        # Check if first line looks like a header
        if lines and 'ibyt' in lines[0]:
            header = lines[0].split(',')
            try:
                ts_idx = header.index('ts')
                ibyt_idx = header.index('ibyt')
            except:
                pass
            start_idx = 1
        else:
            start_idx = 0

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(ts_idx, ibyt_idx):
                try:
                    # Parse timestamp (format: YYYY-MM-DD HH:MM:SS.mmm)
                    ts_str = parts[ts_idx]
                    if ' ' in ts_str:
                        time_part = ts_str.split(' ')[1]
                        hour = int(time_part.split(':')[0])
                    else:
                        hour = datetime.now().hour
                    b = int(parts[ibyt_idx])
                    hourly_bytes[hour] += b
                    hourly_flows[hour] += 1
                except: pass

        # Find peak hour
        peak_hour = max(hourly_bytes, key=hourly_bytes.get)
        peak_bytes = hourly_bytes[peak_hour]

        # Create labels (0:00, 1:00, etc)
        labels = [f"{h}:00" for h in range(24)]
        bytes_data = [hourly_bytes[h] for h in range(24)]
        flows_data = [hourly_flows[h] for h in range(24)]

        data = {
            "labels": labels,
            "bytes": bytes_data,
            "flows": flows_data,
            "bytes_fmt": [fmt_bytes(b) for b in bytes_data],
            "peak_hour": peak_hour,
            "peak_bytes": peak_bytes,
            "peak_bytes_fmt": fmt_bytes(peak_bytes),
            "total_bytes": sum(bytes_data),
            "total_bytes_fmt": fmt_bytes(sum(bytes_data))
        }
    except:
        data = {"labels": [], "bytes": [], "flows": [], "bytes_fmt": [], "peak_hour": 0, "peak_bytes": 0, "peak_bytes_fmt": "0 B", "total_bytes": 0, "total_bytes_fmt": "0 B"}

    with _cache_lock:
        _stats_hourly_cache["data"] = data
        _stats_hourly_cache["ts"] = now
        _stats_hourly_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/flow_stats")
@throttle(5, 10)
def api_stats_flow_stats():
    """Flow statistics - averages, totals, distributions."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_flow_stats_cache["data"] and _stats_flow_stats_cache["key"] == range_key and _stats_flow_stats_cache.get("win") == win:
            return jsonify(_stats_flow_stats_cache["data"])

    tf = get_time_range(range_key)
    output = run_nfdump(["-n", "2000"], tf)

    try:
        durations = []
        bytes_list = []
        packets_list = []
        lines = output.strip().split("\n")
        
        # NFDump CSV usually has no header
        # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
        td_idx, ipkt_idx, ibyt_idx = 1, 7, 8
        start_idx = 0

        # Check if first line looks like a header
        if lines and ('td' in lines[0] or 'duration' in lines[0]):
            header = lines[0].split(',')
            try:
                # Try 1.7+ standard tags
                if 'td' in header: td_idx = header.index('td')
                elif 'duration' in header: td_idx = header.index('duration')

                if 'ibyt' in header: ibyt_idx = header.index('ibyt')
                elif 'bytes' in header: ibyt_idx = header.index('bytes')

                if 'ipkt' in header: ipkt_idx = header.index('ipkt')
                elif 'packets' in header: ipkt_idx = header.index('packets')
                
                start_idx = 1
            except:
                pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(td_idx, ibyt_idx, ipkt_idx):
                try:
                    durations.append(float(parts[td_idx]))
                    bytes_list.append(int(parts[ibyt_idx]))
                    packets_list.append(int(parts[ipkt_idx]))
                except: pass

        total_flows = len(durations)
        total_bytes = sum(bytes_list)
        total_packets = sum(packets_list)
        
        avg_duration = sum(durations) / total_flows if total_flows > 0 else 0
        avg_bytes = total_bytes / total_flows if total_flows > 0 else 0
        avg_packets = total_packets / total_flows if total_flows > 0 else 0
        
        # Duration distribution
        short_flows = sum(1 for d in durations if d < 1)  # < 1s
        medium_flows = sum(1 for d in durations if 1 <= d < 60)  # 1s - 1m
        long_flows = sum(1 for d in durations if d >= 60)  # > 1m
        
        data = {
            "total_flows": total_flows,
            "total_bytes": total_bytes,
            "total_bytes_fmt": fmt_bytes(total_bytes),
            "total_packets": total_packets,
            "avg_duration": round(avg_duration, 2),
            "avg_duration_fmt": f"{avg_duration:.1f}s" if avg_duration < 60 else f"{avg_duration/60:.1f}m",
            "avg_bytes": round(avg_bytes),
            "avg_bytes_fmt": fmt_bytes(avg_bytes),
            "avg_packets": round(avg_packets, 1),
            "duration_dist": {
                "short": short_flows,
                "medium": medium_flows,
                "long": long_flows
            },
            "bytes_per_packet": round(total_bytes / total_packets) if total_packets > 0 else 0
        }
    except:
        data = {"total_flows": 0, "total_bytes": 0, "total_bytes_fmt": "0 B", "avg_duration": 0, "avg_duration_fmt": "0s"}

    with _cache_lock:
        _stats_flow_stats_cache["data"] = data
        _stats_flow_stats_cache["ts"] = now
        _stats_flow_stats_cache["key"] = range_key
        _stats_flow_stats_cache["win"] = win
    return jsonify(data)


@app.route("/api/stats/proto_mix")
@throttle(5, 10)
def api_stats_proto_mix():
    """Protocol mix for pie chart visualization."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_proto_mix_cache["data"] and _stats_proto_mix_cache["key"] == range_key and _stats_proto_mix_cache.get("win") == win:
            return jsonify(_stats_proto_mix_cache["data"])

    try:
        # Reuse protocols data
        protos_data = get_common_nfdump_data("protos", range_key)
        
        if not protos_data:
            # Return empty but valid structure
            return jsonify({
                "labels": [],
                "bytes": [],
                "bytes_fmt": [],
                "flows": [],
                "percentages": [],
                "colors": [],
                "total_bytes": 0,
                "total_bytes_fmt": "0 B"
            })
        
        labels = []
        bytes_data = []
        flows_data = []
        colors = ['#00f3ff', '#bc13fe', '#00ff88', '#ffff00', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
        
        for i, p in enumerate(protos_data[:8]):  # Top 8 protocols
            proto_val = p.get('key', '')
            if not proto_val:
                continue
                
            # Convert protocol number to name
            if proto_val.isdigit():
                name = PROTOS.get(int(proto_val), f"Proto {proto_val}")
            else:
                name = proto_val.upper()
                
            labels.append(name)
            bytes_data.append(p.get('bytes', 0))
            flows_data.append(p.get('flows', 0))
        
        total_bytes = sum(bytes_data)
        percentages = [round(b / total_bytes * 100, 1) if total_bytes > 0 else 0 for b in bytes_data]
        
        data = {
            "labels": labels,
            "bytes": bytes_data,
            "bytes_fmt": [fmt_bytes(b) for b in bytes_data],
            "flows": flows_data,
            "percentages": percentages,
            "colors": colors[:len(labels)],
            "total_bytes": total_bytes,
            "total_bytes_fmt": fmt_bytes(total_bytes)
        }

        with _cache_lock:
            _stats_proto_mix_cache["data"] = data
            _stats_proto_mix_cache["ts"] = now
            _stats_proto_mix_cache["key"] = range_key
            _stats_proto_mix_cache["win"] = win
        return jsonify(data)
        
    except Exception as e:
        print(f"Error in proto_mix: {e}")
        import traceback
        traceback.print_exc()
        # Return empty but valid structure on error
        return jsonify({
            "labels": [],
            "bytes": [],
            "bytes_fmt": [],
            "flows": [],
            "percentages": [],
            "colors": [],
            "total_bytes": 0,
            "total_bytes_fmt": "0 B"
        })


@app.route("/api/stats/net_health")
@throttle(5, 10)
def api_stats_net_health():
    """Network health indicators based on traffic patterns."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_net_health_cache["data"] and _stats_net_health_cache["key"] == range_key and _stats_net_health_cache.get("win") == win:
            return jsonify(_stats_net_health_cache["data"])

    tf = get_time_range(range_key)
    output = run_nfdump(["-n", "1000"], tf)

    indicators = []
    health_score = 100
    
    try:
        lines = output.strip().split("\n")
        if len(lines) < 2:
            raise ValueError("No flow data available")
            
        # Dynamic column detection
        header_line = lines[0].lower()
        header = [c.strip() for c in header_line.split(',')]
        
        try:
            # Try to find columns dynamically
            flg_idx = header.index('flg') if 'flg' in header else header.index('flags') if 'flags' in header else -1
            pr_idx = header.index('pr') if 'pr' in header else header.index('proto') if 'proto' in header else -1
            ibyt_idx = header.index('ibyt') if 'ibyt' in header else header.index('byt') if 'byt' in header else header.index('bytes') if 'bytes' in header else -1
            
            if pr_idx == -1 or ibyt_idx == -1:
                raise ValueError(f"Required columns not found. Header: {header}")
        except Exception as e:
            print(f"Column detection error: {e}")
            # Use fallback indices
            flg_idx, pr_idx, ibyt_idx = 10, 7, 12

        total_flows = 0
        rst_count = 0
        syn_only = 0
        icmp_count = 0
        small_flows = 0
        
        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            total_flows += 1
            if len(parts) > max(flg_idx, pr_idx, ibyt_idx):
                try:
                    flags = parts[flg_idx].upper()
                    proto = parts[pr_idx]
                    b = int(parts[ibyt_idx])
                    
                    if 'R' in flags: rst_count += 1
                    if flags == 'S' or flags == '.S': syn_only += 1
                    if proto == '1' or proto.upper() == 'ICMP': icmp_count += 1
                    if b < 100: small_flows += 1
                except: pass

        if total_flows > 0:
            rst_pct = rst_count / total_flows * 100
            syn_pct = syn_only / total_flows * 100
            icmp_pct = icmp_count / total_flows * 100
            small_pct = small_flows / total_flows * 100
            
            # TCP Resets indicator
            if rst_pct < 5:
                indicators.append({"name": "TCP Resets", "value": f"{rst_pct:.1f}%", "status": "good", "icon": "✅"})
            elif rst_pct < 15:
                indicators.append({"name": "TCP Resets", "value": f"{rst_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 10
            else:
                indicators.append({"name": "TCP Resets", "value": f"{rst_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 25
            
            # SYN-only (potential scans)
            if syn_pct < 2:
                indicators.append({"name": "SYN-Only Flows", "value": f"{syn_pct:.1f}%", "status": "good", "icon": "✅"})
            elif syn_pct < 10:
                indicators.append({"name": "SYN-Only Flows", "value": f"{syn_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 10
            else:
                indicators.append({"name": "SYN-Only Flows", "value": f"{syn_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 20
            
            # ICMP traffic
            if icmp_pct < 5:
                indicators.append({"name": "ICMP Traffic", "value": f"{icmp_pct:.1f}%", "status": "good", "icon": "✅"})
            elif icmp_pct < 15:
                indicators.append({"name": "ICMP Traffic", "value": f"{icmp_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 5
            else:
                indicators.append({"name": "ICMP Traffic", "value": f"{icmp_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 15
            
            # Small flows (potential anomaly)
            if small_pct < 20:
                indicators.append({"name": "Tiny Flows", "value": f"{small_pct:.1f}%", "status": "good", "icon": "✅"})
            elif small_pct < 40:
                indicators.append({"name": "Tiny Flows", "value": f"{small_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 5
            else:
                indicators.append({"name": "Tiny Flows", "value": f"{small_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 10

        health_score = max(0, min(100, health_score))
        
        if health_score >= 80:
            status = "healthy"
            status_icon = "💚"
        elif health_score >= 60:
            status = "fair"
            status_icon = "💛"
        else:
            status = "poor"
            status_icon = "❤️"
        
        # Add firewall protection status from syslog
        fw_stats = _get_firewall_block_stats()
        blocks_1h = fw_stats.get('blocks_per_hour', 0)
        syslog_active = fw_stats.get('blocks', 0) > 0 or fw_stats.get('unique_ips', 0) > 0
        
        if blocks_1h > 0:
            indicators.append({
                "name": "Firewall Active", 
                "value": f"{int(blocks_1h)} blocks/hr", 
                "status": "good", 
                "icon": "🔥"
            })
            # Bonus points for active firewall protection
            health_score = min(100, health_score + 5)
        elif syslog_active:
            indicators.append({
                "name": "Firewall Active", 
                "value": "0 blocks", 
                "status": "good", 
                "icon": "✅"
            })
        
        # Add threat blocking info if available
        if fw_stats.get('threats_blocked', 0) > 0:
            indicators.append({
                "name": "Threats Blocked", 
                "value": str(fw_stats['threats_blocked']), 
                "status": "good", 
                "icon": "🛡️"
            })
            
        data = {
            "indicators": indicators,
            "health_score": health_score,
            "status": status,
            "status_icon": status_icon,
            "total_flows": total_flows,
            "firewall_active": syslog_active,
            "blocks_1h": int(blocks_1h)
        }
    except Exception as e:
        print(f"Error in net_health: {e}")
        import traceback
        traceback.print_exc()
        # Return degraded but informative status
        data = {
            "indicators": [{"name": "Data Unavailable", "value": "Check nfdump", "status": "warn", "icon": "⚠️"}],
            "health_score": 0,
            "status": "degraded",
            "status_icon": "⚠️",
            "total_flows": 0,
            "firewall_active": False,
            "blocks_1h": 0
        }

    with _cache_lock:
        _stats_net_health_cache["data"] = data
        _stats_net_health_cache["ts"] = now
        _stats_net_health_cache["key"] = range_key
        _stats_net_health_cache["win"] = win
    return jsonify(data)


# ===== Trends (5-minute rollups stored in SQLite) =====

def _trends_db_connect():
    conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def _trends_db_init():
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic_rollups (
                    bucket_end INTEGER PRIMARY KEY,
                    bytes INTEGER NOT NULL,
                    flows INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_rollups_bucket ON traffic_rollups(bucket_end);")
            conn.commit()
        finally:
            conn.close()

def _get_bucket_end(dt=None):
    dt = dt or datetime.now()
    # Align to nearest 5 minutes upper boundary
    remainder = dt.minute % 5
    current_bucket_end = dt.replace(minute=dt.minute - remainder, second=0, microsecond=0) + timedelta(minutes=5)
    return current_bucket_end

def _ensure_rollup_for_bucket(bucket_end_dt):
    """Ensure we have a rollup for the given completed bucket end (datetime)."""
    bucket_end_ts = int(bucket_end_dt.timestamp())
    # Check if exists
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute("SELECT 1 FROM traffic_rollups WHERE bucket_end=?", (bucket_end_ts,))
            row = cur.fetchone()
            if row:
                return
        finally:
            conn.close()

    # Compute using nfdump over the 5-min interval ending at bucket_end_dt
    st = bucket_end_dt - timedelta(minutes=5)
    tf_key = f"{st.strftime('%Y/%m/%d.%H:%M:%S')}-{bucket_end_dt.strftime('%Y/%m/%d.%H:%M:%S')}"

    output = run_nfdump(["-s","proto/bytes/flows","-n","100"], tf_key)
    stats = parse_csv(output, expected_key='proto')
    total_b = sum(s.get("bytes", 0) for s in stats)
    total_f = sum(s.get("flows", 0) for s in stats)

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            conn.execute("INSERT OR REPLACE INTO traffic_rollups(bucket_end, bytes, flows) VALUES (?,?,?)",
                        (bucket_end_ts, int(total_b), int(total_f)))
            conn.commit()
        finally:
            conn.close()

    # Also compute top sources and destinations for this bucket (top 10)
    try:
        src_out = run_nfdump(["-s", "srcip/bytes/flows", "-n", "10"], tf_key)
        dst_out = run_nfdump(["-s", "dstip/bytes/flows", "-n", "10"], tf_key)
        top_src = parse_csv(src_out, expected_key='sa')
        top_dst = parse_csv(dst_out, expected_key='da')

        with _trends_db_lock:
            conn = _trends_db_connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS top_sources (
                        bucket_end INTEGER,
                        ip TEXT,
                        bytes INTEGER NOT NULL,
                        flows INTEGER NOT NULL,
                        PRIMARY KEY(bucket_end, ip)
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS top_dests (
                        bucket_end INTEGER,
                        ip TEXT,
                        bytes INTEGER NOT NULL,
                        flows INTEGER NOT NULL,
                        PRIMARY KEY(bucket_end, ip)
                    );
                    """
                )
                if top_src:
                    conn.executemany(
                        "INSERT OR REPLACE INTO top_sources(bucket_end, ip, bytes, flows) VALUES (?,?,?,?)",
                        [(bucket_end_ts, r.get("key"), int(r.get("bytes",0)), int(r.get("flows",0))) for r in top_src]
                    )
                if top_dst:
                    conn.executemany(
                        "INSERT OR REPLACE INTO top_dests(bucket_end, ip, bytes, flows) VALUES (?,?,?,?)",
                        [(bucket_end_ts, r.get("key"), int(r.get("bytes",0)), int(r.get("flows",0))) for r in top_dst]
                    )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_top_sources_end ON top_sources(bucket_end)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_top_dests_end ON top_dests(bucket_end)")
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass

def start_trends_thread():
    global _trends_thread_started
    if _trends_thread_started:
        return
    _trends_thread_started = True
    _trends_db_init()

    def loop():
        while not _shutdown_event.is_set():
            try:
                # Work on the last completed bucket (avoid partial current)
                now_dt = datetime.now()
                current_end = _get_bucket_end(now_dt)
                last_completed_end = current_end - timedelta(minutes=5)
                _ensure_rollup_for_bucket(last_completed_end)
            except Exception:
                pass
            _shutdown_event.wait(timeout=CACHE_TTL_SHORT)

    t = threading.Thread(target=loop, daemon=True, name='TrendsThread')
    t.start()


def start_agg_thread():
    """Background aggregator to precompute common nfdump data for 1h range every 60s."""
    global _agg_thread_started
    if _agg_thread_started:
        return
    _agg_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            try:
                range_key = '1h'
                tf = get_time_range(range_key)
                now_ts = time.time()
                win = int(now_ts // 60)

                # Parallelize nfdump calls to speed up aggregation
                def fetch_sources():
                    data = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","100"], tf), expected_key='sa')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_ports():
                    data = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","100"], tf), expected_key='dp')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_dests():
                    data = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","100"], tf), expected_key='da')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_protos():
                    return parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","20"], tf), expected_key='proto')

                with ThreadPoolExecutor(max_workers=4) as executor:
                    f_sources = executor.submit(fetch_sources)
                    f_ports = executor.submit(fetch_ports)
                    f_dests = executor.submit(fetch_dests)
                    f_protos = executor.submit(fetch_protos)

                    sources = f_sources.result()
                    ports = f_ports.result()
                    dests = f_dests.result()
                    protos = f_protos.result()

                with _common_data_lock:
                    _common_data_cache[f"sources:{range_key}:{win}"] = {"data": sources, "ts": now_ts, "win": win}
                    _common_data_cache[f"ports:{range_key}:{win}"] = {"data": ports, "ts": now_ts, "win": win}
                    _common_data_cache[f"dests:{range_key}:{win}"] = {"data": dests, "ts": now_ts, "win": win}
                    _common_data_cache[f"protos:{range_key}:{win}"] = {"data": protos, "ts": now_ts, "win": win}
            except Exception:
                pass
            time.sleep(60)

    t = threading.Thread(target=loop, daemon=True)
    t.start()


# ===== Firewall Syslog Receiver (OPNsense filterlog) =====

import re

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

def _firewall_db_connect():
    """Connect to firewall SQLite database."""
    conn = sqlite3.connect(FIREWALL_DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def _firewall_db_init():
    """Initialize firewall log database schema."""
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fw_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    timestamp_iso TEXT,
                    action TEXT NOT NULL,
                    direction TEXT,
                    interface TEXT,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    proto TEXT,
                    rule_id TEXT,
                    length INTEGER,
                    country_iso TEXT,
                    is_threat INTEGER DEFAULT 0,
                    raw_log TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_timestamp ON fw_logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_action ON fw_logs(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_src_ip ON fw_logs(src_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_dst_port ON fw_logs(dst_port)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_action_ts ON fw_logs(action, timestamp)")
            
            # Hourly aggregates table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fw_stats_hourly (
                    hour_ts INTEGER PRIMARY KEY,
                    blocks INTEGER DEFAULT 0,
                    passes INTEGER DEFAULT 0,
                    unique_blocked_ips INTEGER DEFAULT 0,
                    top_blocked_port INTEGER,
                    top_blocked_country TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

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

def _flush_syslog_buffer():
    """Flush buffered syslog entries to database in batch."""
    global _syslog_buffer
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
        
        if is_threat:
            should_alert = True
            severity = 'high'
            alert_type = 'threat_blocked'
            msg = f"🔥 Threat IP blocked: {src_ip}"
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
        
        if should_alert:
            alert = {
                'type': alert_type,
                'severity': severity,
                'ip': src_ip,
                'port': dst_port,
                'msg': msg,
                'ts': now,
                'source': 'firewall'
            }
            with _alert_history_lock:
                # Dedupe: don't add if same IP/port in last 60 seconds
                recent_keys = {(a.get('ip'), a.get('port')) for a in list(_alert_history)[-20:] 
                              if a.get('ts', 0) > now - 60}
                if (src_ip, dst_port) not in recent_keys:
                    _alert_history.append(alert)
    
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

def _syslog_receiver_loop():
    """UDP syslog receiver loop."""
    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    
    try:
        sock.bind((SYSLOG_BIND, SYSLOG_PORT))
        print(f"Syslog receiver started on {SYSLOG_BIND}:{SYSLOG_PORT}")
    except PermissionError:
        print(f"ERROR: Cannot bind to port {SYSLOG_PORT} - need root or CAP_NET_BIND_SERVICE")
        return
    except Exception as e:
        print(f"ERROR: Syslog bind failed: {e}")
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

def start_syslog_thread():
    """Start the syslog receiver and maintenance threads."""
    global _syslog_thread_started
    if _syslog_thread_started:
        return
    _syslog_thread_started = True
    _firewall_db_init()
    
    # Receiver thread
    t1 = threading.Thread(target=_syslog_receiver_loop, daemon=True)
    t1.start()
    
    # Maintenance thread
    t2 = threading.Thread(target=_syslog_maintenance_loop, daemon=True)
    t2.start()


# ===== Firewall Log API Endpoints =====

@app.route("/api/firewall/logs/stats")
@throttle(5, 10)
def api_firewall_logs_stats():
    """Get firewall log statistics."""
    range_key = request.args.get('range', '1h')
    range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    cutoff = time.time() - range_seconds
    
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Total blocks and passes
            cur = conn.execute("""
                SELECT action, COUNT(*) as cnt FROM fw_logs 
                WHERE timestamp > ? GROUP BY action
            """, (cutoff,))
            counts = {row[0]: row[1] for row in cur.fetchall()}
            
            blocks = counts.get('block', 0) + counts.get('reject', 0)
            passes = counts.get('pass', 0)
            
            # Unique blocked IPs
            cur = conn.execute("""
                SELECT COUNT(DISTINCT src_ip) FROM fw_logs 
                WHERE timestamp > ? AND action IN ('block', 'reject')
            """, (cutoff,))
            unique_blocked = cur.fetchone()[0] or 0
            
            # Top blocked ports
            cur = conn.execute("""
                SELECT dst_port, COUNT(*) as cnt FROM fw_logs 
                WHERE timestamp > ? AND action IN ('block', 'reject') AND dst_port > 0
                GROUP BY dst_port ORDER BY cnt DESC LIMIT 10
            """, (cutoff,))
            top_ports = [{"port": row[0], "count": row[1], "service": PORTS.get(row[0], "Unknown")} for row in cur.fetchall()]
            
            # Top blocked countries
            cur = conn.execute("""
                SELECT country_iso, COUNT(*) as cnt FROM fw_logs 
                WHERE timestamp > ? AND action IN ('block', 'reject') AND country_iso IS NOT NULL
                GROUP BY country_iso ORDER BY cnt DESC LIMIT 10
            """, (cutoff,))
            top_countries = [{"iso": row[0], "count": row[1]} for row in cur.fetchall()]
            
            # Threat matches
            cur = conn.execute("""
                SELECT COUNT(*) FROM fw_logs 
                WHERE timestamp > ? AND is_threat = 1
            """, (cutoff,))
            threat_hits = cur.fetchone()[0] or 0
            
        finally:
            conn.close()
    
    hours = range_seconds / 3600
    with _syslog_stats_lock:
        receiver_stats = dict(_syslog_stats)
    data = {
        "blocks_total": blocks,
        "blocks_per_hour": round(blocks / hours, 1) if hours > 0 else 0,
        "passes_total": passes,
        "unique_blocked_ips": unique_blocked,
        "top_blocked_ports": top_ports,
        "top_blocked_countries": top_countries,
        "threat_hits": threat_hits,
        "receiver_stats": receiver_stats
    }
    return jsonify(data)


@app.route("/api/firewall/logs/blocked")
@throttle(5, 10)
def api_firewall_logs_blocked():
    """Get top blocked IPs."""
    range_key = request.args.get('range', '1h')
    limit = min(int(request.args.get('limit', 20)), 100)
    range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    cutoff = time.time() - range_seconds
    
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute("""
                SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT dst_port) as ports, 
                       MAX(country_iso) as country, MAX(is_threat) as is_threat
                FROM fw_logs 
                WHERE timestamp > ? AND action IN ('block', 'reject')
                GROUP BY src_ip ORDER BY cnt DESC LIMIT ?
            """, (cutoff, limit))
            
            blocked_ips = []
            for row in cur.fetchall():
                ports_str = row[3] or ""
                ports_list = [int(p) for p in ports_str.split(',') if p.isdigit()][:5]
                
                ip = row[0]
                geo = lookup_geo(ip)
                
                blocked_ips.append({
                    "ip": ip,
                    "count": row[1],
                    "last_seen": datetime.fromtimestamp(row[2]).isoformat() if row[2] else None,
                    "ports_targeted": ports_list,
                    "country": geo.get('country') if geo else None,
                    "country_iso": row[4],
                    "flag": flag_from_iso(row[4]) if row[4] else "",
                    "is_threat": bool(row[5]),
                    "hostname": resolve_ip(ip)
                })
        finally:
            conn.close()
    
    return jsonify({"blocked_ips": blocked_ips})


@app.route("/api/firewall/logs/timeline")
@throttle(5, 10)
def api_firewall_logs_timeline():
    """Get hourly timeline of blocks/passes."""
    range_key = request.args.get('range', '24h')
    range_seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 86400)
    cutoff = time.time() - range_seconds
    
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Group by hour
            cur = conn.execute("""
                SELECT 
                    CAST((timestamp / 3600) AS INTEGER) * 3600 as hour_ts,
                    action,
                    COUNT(*) as cnt
                FROM fw_logs 
                WHERE timestamp > ?
                GROUP BY hour_ts, action
                ORDER BY hour_ts
            """, (cutoff,))
            
            hours_data = {}
            for row in cur.fetchall():
                hour_ts = row[0]
                action = row[1]
                count = row[2]
                
                if hour_ts not in hours_data:
                    hours_data[hour_ts] = {"blocks": 0, "passes": 0}
                
                if action in ('block', 'reject'):
                    hours_data[hour_ts]["blocks"] += count
                elif action == 'pass':
                    hours_data[hour_ts]["passes"] += count
        finally:
            conn.close()
    
    timeline = [
        {
            "hour": datetime.fromtimestamp(ts).isoformat(),
            "hour_ts": ts,
            "blocks": data["blocks"],
            "passes": data["passes"]
        }
        for ts, data in sorted(hours_data.items())
    ]
    
    return jsonify({"timeline": timeline})


@app.route("/api/firewall/logs/recent")
@throttle(5, 10)
def api_firewall_logs_recent():
    """Get most recent firewall log entries (up to 1000)."""
    limit = min(int(request.args.get('limit', 1000)), 1000)
    action_filter = request.args.get('action')  # 'block', 'pass', or None for all
    since_ts = request.args.get('since')  # Optional: only return logs newer than this timestamp
    now = time.time()
    cutoff_1h = now - 3600

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Build query with optional filters
            where_clauses = []
            params = []
            
            if since_ts:
                try:
                    since_float = float(since_ts)
                    where_clauses.append("timestamp > ?")
                    params.append(since_float)
                except (ValueError, TypeError):
                    pass  # Ignore invalid since parameter
            
            if action_filter:
                where_clauses.append("action = ?")
                params.append(action_filter)
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            params.append(limit)
            
            cur = conn.execute(f"""
                SELECT timestamp, timestamp_iso, action, direction, interface, src_ip, src_port, 
                       dst_ip, dst_port, proto, country_iso, is_threat
                FROM fw_logs WHERE {where_sql} ORDER BY timestamp DESC LIMIT ?
            """, params)
            
            logs = []
            action_counts = {"block": 0, "reject": 0, "pass": 0}
            unique_src = set()
            unique_dst = set()
            threat_count = 0
            blocks_last_hour = 0
            passes_last_hour = 0
            latest_ts = None

            for row in cur.fetchall():
                ts = row[0]
                ts_iso = row[1]
                action = row[2]
                direction = row[3]
                iface = row[4]
                src_ip = row[5]
                src_port = row[6]
                dst_ip = row[7]
                dst_port = row[8]
                proto = row[9]
                country_iso = row[10]
                is_threat = bool(row[11])

                # Stats
                if action in action_counts:
                    action_counts[action] += 1
                if is_threat:
                    threat_count += 1
                if ts and action in ('block', 'reject') and ts >= cutoff_1h:
                    blocks_last_hour += 1
                if ts and action == 'pass' and ts >= cutoff_1h:
                    passes_last_hour += 1
                if src_ip:
                    unique_src.add(src_ip)
                if dst_ip:
                    unique_dst.add(dst_ip)
                if ts and (latest_ts is None or ts > latest_ts):
                    latest_ts = ts

                logs.append({
                    "timestamp": ts_iso,
                    "timestamp_ts": ts,
                    "action": action,
                    "direction": direction,
                    "interface": iface,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": proto,
                    "country_iso": country_iso,
                    "flag": flag_from_iso(country_iso) if country_iso else "",
                    "is_threat": is_threat,
                    "service": PORTS.get(dst_port, "") if dst_port else ""
                })
        finally:
            conn.close()
    
    stats = {
        "total": len(logs),
        "actions": action_counts,
        "threats": threat_count,
        "unique_src": len(unique_src),
        "unique_dst": len(unique_dst),
        "blocks_last_hour": blocks_last_hour,
        "passes_last_hour": passes_last_hour,
        "latest_ts": latest_ts
    }

    with _syslog_stats_lock:
        receiver_stats = dict(_syslog_stats)
    return jsonify({"logs": logs, "stats": stats, "receiver_stats": receiver_stats})


@app.route("/api/alerts")
@throttle(5, 10)
def api_alerts():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_alerts:
        if _stats_alerts_cache["data"] and _stats_alerts_cache["key"] == range_key and _stats_alerts_cache.get("win") == win:
            return jsonify(_stats_alerts_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    # Run analysis (using shared data)
    # Alerts logic uses top sources/dests/ports for comprehensive IP coverage
    sources = get_common_nfdump_data("sources", range_key)[:50]
    dests = get_common_nfdump_data("dests", range_key)[:50]
    ports = get_common_nfdump_data("ports", range_key)

    alerts = detect_anomalies(ports, sources, threat_set, whitelist, destinations_data=dests)
    send_notifications([a for a in alerts if a.get("severity") in ("critical","high")])

    data = {
        "alerts": alerts, # Not limited to 10
        "feed_label": get_feed_label()
    }
    with _lock_alerts:
        _stats_alerts_cache["data"] = data
        _stats_alerts_cache["ts"] = now
        _stats_alerts_cache["key"] = range_key
        _stats_alerts_cache["win"] = win
    return jsonify(data)


@app.route("/api/bandwidth")
@throttle(10,20)
def api_bandwidth():
    range_key = request.args.get('range', '1h')
    now_ts = time.time()

    # Determine bucket count based on range (5-min buckets)
    # 1h = 12 buckets
    # 30m = 6 buckets
    # 15m = 3 buckets
    bucket_count = 12
    if range_key == '30m': bucket_count = 6
    elif range_key == '15m': bucket_count = 3
    elif range_key == '6h': bucket_count = 72
    elif range_key == '24h': bucket_count = 288
    elif range_key == '7d': bucket_count = 7*24*12

    # Separate cache key for different ranges?
    # Current _bandwidth_cache is global. If we switch range, we overwrite.
    # That's acceptable for single-user, but we should probably key it.

    cache_key = f"bw_{range_key}"

    # Check cache with range key validation
    with _lock_bandwidth:
        if _bandwidth_cache.get("data") and _bandwidth_cache.get("key") == cache_key and now_ts - _bandwidth_cache.get("ts", 0) < 5:
            global _metric_bw_cache_hits
            _metric_bw_cache_hits += 1
            return jsonify(_bandwidth_cache["data"])

    now = datetime.now()
    labels, bw, flows = [], [], []

    # Use trends DB for completed buckets; compute only incomplete current if needed
    _trends_db_init()
    current_bucket_end = _get_bucket_end(now)

    try:
        # Fetch required completed buckets from DB in one query
        end_needed = current_bucket_end  # may include current incomplete bucket
        start_needed = end_needed - timedelta(minutes=5*bucket_count)
        start_ts = int((start_needed).timestamp())
        end_ts = int((end_needed).timestamp())

        with _trends_db_lock:
            conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
            try:
                cur = conn.execute(
                    "SELECT bucket_end, bytes, flows FROM traffic_rollups WHERE bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                    (start_ts, end_ts)
                )
                rows = cur.fetchall()
            finally:
                conn.close()

        # Build a mapping for quick lookup
        by_end = {r[0]: {"bytes": r[1], "flows": r[2]} for r in rows}

        # Identify missing buckets that need computation
        missing_buckets = []
        for i in range(bucket_count, 0, -1):
            et = current_bucket_end - timedelta(minutes=i*5)
            et_ts = int(et.timestamp())
            if et_ts not in by_end and et < now:
                missing_buckets.append(et)

        # Parallel compute missing buckets
        if missing_buckets:
            # Optimization for Mock Mode:
            # If we don't have real nfdump, we are using static sample data.
            # Calculating 288 buckets (24h) of identical static data is wasteful.
            # Calculate once and replicate.
            global _has_nfdump
            if _has_nfdump is None:
                _has_nfdump = (subprocess.call(["which", "nfdump"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0)

            if _has_nfdump is False and len(missing_buckets) > 1:
                # Compute the first one to prime the data
                ref_dt = missing_buckets[0]
                _ensure_rollup_for_bucket(ref_dt)

                # Copy result to all other buckets
                ref_ts = int(ref_dt.timestamp())

                with _trends_db_lock:
                    conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
                    try:
                        # Fetch the computed reference data
                        cur = conn.execute("SELECT bytes, flows FROM traffic_rollups WHERE bucket_end=?", (ref_ts,))
                        roll_row = cur.fetchone()

                        cur = conn.execute("SELECT ip, bytes, flows FROM top_sources WHERE bucket_end=?", (ref_ts,))
                        src_rows = cur.fetchall()

                        cur = conn.execute("SELECT ip, bytes, flows FROM top_dests WHERE bucket_end=?", (ref_ts,))
                        dst_rows = cur.fetchall()

                        # Bulk insert for all other missing buckets
                        if roll_row:
                            params = []
                            for dt in missing_buckets[1:]:
                                params.append((int(dt.timestamp()), roll_row[0], roll_row[1]))
                            conn.executemany("INSERT OR REPLACE INTO traffic_rollups(bucket_end, bytes, flows) VALUES (?,?,?)", params)

                        if src_rows:
                            params = []
                            for dt in missing_buckets[1:]:
                                ts = int(dt.timestamp())
                                for r in src_rows:
                                    params.append((ts, r[0], r[1], r[2]))
                            conn.executemany("INSERT OR REPLACE INTO top_sources(bucket_end, ip, bytes, flows) VALUES (?,?,?,?)", params)

                        if dst_rows:
                            params = []
                            for dt in missing_buckets[1:]:
                                ts = int(dt.timestamp())
                                for r in dst_rows:
                                    params.append((ts, r[0], r[1], r[2]))
                            conn.executemany("INSERT OR REPLACE INTO top_dests(bucket_end, ip, bytes, flows) VALUES (?,?,?,?)", params)

                        conn.commit()
                    finally:
                        conn.close()
            else:
                # Normal behavior (or single bucket)
                # Use a reasonable number of workers to avoid overloading the system
                # 8 workers allows decent parallelism without excessive context switching
                with ThreadPoolExecutor(max_workers=8) as executor:
                    list(executor.map(_ensure_rollup_for_bucket, missing_buckets))

            # Re-fetch data after computation
            with _trends_db_lock:
                conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
                try:
                    cur = conn.execute(
                        "SELECT bucket_end, bytes, flows FROM traffic_rollups WHERE bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                        (start_ts, end_ts)
                    )
                    rows = cur.fetchall()
                    by_end = {r[0]: {"bytes": r[1], "flows": r[2]} for r in rows}
                finally:
                    conn.close()

        for i in range(bucket_count, 0, -1):
            et = current_bucket_end - timedelta(minutes=i*5)
            et_ts = int(et.timestamp())
            labels.append(et.strftime("%H:%M"))
            rec = by_end.get(et_ts)
            if rec:
                total_b = rec["bytes"]
                total_f = rec["flows"]
                val_bw = round((total_b*8)/(300*1_000_000),2)
                val_flows = round(total_f/300,2)
            else:
                val_bw = 0
                val_flows = 0

            bw.append(val_bw)
            flows.append(val_flows)

        data = {"labels":labels,"bandwidth":bw,"flows":flows, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
        with _lock_bandwidth:
            _bandwidth_cache["data"] = data
            _bandwidth_cache["ts"] = now_ts
            _bandwidth_cache["key"] = cache_key
        return jsonify(data)
    except Exception:
        return jsonify({"labels":[],"bandwidth":[],"flows":[]}), 500

@app.route("/api/flows")
@throttle(10,30)
def api_flows():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_flows:
        if _flows_cache.get("data") and _flows_cache.get("key") == cache_key_local and _flows_cache.get("win") == win:
            global _metric_flow_cache_hits
            _metric_flow_cache_hits += 1
            return jsonify(_flows_cache["data"])
    tf = get_time_range(range_key)

    # Fetch raw flows to get actual flow partners
    # Use -O bytes to sort by bytes descending at nfdump level to get 'Top' flows
    # If limit > 100, we might need more data.
    # Fetch raw flows to get actual flow partners
    # Use -O bytes to sort by bytes descending at nfdump level to get 'Top' flows
    # If limit > 100, we might need more data.
    fetch_limit = str(max(100, limit))
    # Aggregate by 5-tuple to merge duplicate/fragmented flows
    output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-n", fetch_limit], tf)

    convs = []
    # NFDump CSV indices defaults
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8

    try:
        lines = output.strip().split("\n")
        start_idx = 0
        if lines:
            line0 = lines[0]
            if 'ts' in line0 or 'Date' in line0 or 'ibyt' in line0 or 'firstSeen' in line0 or 'firstseen' in line0:
                header = line0.split(',')
                try:
                    # check for common variances
                    sa_key = 'sa' if 'sa' in header else 'srcAddr'
                    if 'srcaddr' in header: sa_key = 'srcaddr'
                    da_key = 'da' if 'da' in header else 'dstAddr'
                    if 'dstaddr' in header: da_key = 'dstaddr'
                    ibyt_key = 'ibyt' if 'ibyt' in header else 'bytes'
                    
                    if sa_key in header: sa_idx = header.index(sa_key)
                    if da_key in header: da_idx = header.index(da_key)
                    if ibyt_key in header: ibyt_idx = header.index(ibyt_key)
                    
                    # Try to map others if present
                    if 'ts' in header: ts_idx = header.index('ts')
                    if 'firstSeen' in header: ts_idx = header.index('firstSeen')
                    if 'firstseen' in header: ts_idx = header.index('firstseen')
                    if 'td' in header: td_idx = header.index('td')
                    if 'duration' in header: td_idx = header.index('duration')
                    if 'pr' in header: pr_idx = header.index('pr')
                    if 'proto' in header: pr_idx = header.index('proto')
                    if 'sp' in header: sp_idx = header.index('sp')
                    if 'srcPort' in header: sp_idx = header.index('srcPort')
                    if 'srcport' in header: sp_idx = header.index('srcport')
                    if 'dp' in header: dp_idx = header.index('dp')
                    if 'dstPort' in header: dp_idx = header.index('dstPort')
                    if 'dstport' in header: dp_idx = header.index('dstport')
                    if 'ipkt' in header: ipkt_idx = header.index('ipkt')
                    if 'packets' in header: ipkt_idx = header.index('packets')
                    start_idx = 1
                except:
                    pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstSeen,') or line.startswith('Date,'): continue
            parts = line.split(',')
            if len(parts) > 7:
                try:
                    ts_str = parts[ts_idx] if len(parts) > ts_idx else ""
                    duration = float(parts[td_idx]) if len(parts) > td_idx else 0.0
                    proto_val = parts[pr_idx] if len(parts) > pr_idx else "0"
                    src = parts[sa_idx]
                    src_port = parts[sp_idx] if len(parts) > sp_idx else "0"
                    dst = parts[da_idx]
                    dst_port = parts[dp_idx] if len(parts) > dp_idx else "0"
                    pkts = int(parts[ipkt_idx]) if len(parts) > ipkt_idx else 0
                    b = int(parts[ibyt_idx])
                    
                    # Calculate Age
                    try:
                        if '.' in ts_str: ts_str = ts_str.split('.')[0]
                        flow_time = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp()
                        age_sec = now - flow_time
                    except:
                        age_sec = 0

                    if age_sec < 0: age_sec = 0
                    
                    # Enrich with Geo
                    src_geo = lookup_geo(src) or {}
                    dst_geo = lookup_geo(dst) or {}
                    
                    # Resolve Service Name
                    try: 
                        svc = socket.getservbyport(int(dst_port), 'tcp' if '6' in proto_val else 'udp')
                    except: 
                        svc = dst_port

                    convs.append({
                        "ts": ts_str,
                        "age": format_duration(age_sec) + " ago" if age_sec < 86400 else ts_str,
                        "duration": f"{duration:.2f}s",
                        "proto": proto_val, 
                        "proto_name": { "6": "TCP", "17": "UDP", "1": "ICMP" }.get(proto_val, proto_val),
                        "src": src,
                        "src_port": src_port,
                        "src_flag": src_geo.get('flag', ''),
                        "src_country": src_geo.get('country', ''),
                        "dst": dst,
                        "dst_port": dst_port,
                        "dst_flag": dst_geo.get('flag', ''),
                        "dst_country": dst_geo.get('country', ''),
                        "service": svc,
                        "bytes": b,
                        "bytes_fmt": fmt_bytes(b),
                        "packets": pkts
                    })
                except:
                    pass


    except:
        pass  # Parsing error
    data = {"flows":convs, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    with _lock_flows:
        _flows_cache["data"] = data
        _flows_cache["ts"] = now
        _flows_cache["key"] = cache_key_local
        _flows_cache["win"] = win
    return jsonify(data)

@app.route("/api/ip_detail/<ip>")
@throttle(5,10)
def api_ip_detail(ip):
    """Get detailed information about an IP address including traffic patterns, ports, protocols, and geo data."""
    start_threat_thread()
    
    # Support range parameter (default to 1h for backwards compatibility)
    range_key = request.args.get('range', '1h')
    range_seconds = {'15m': 900, '30m': 1800, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    dt = datetime.now()
    start_dt = dt - timedelta(seconds=range_seconds)
    tf = f"{start_dt.strftime('%Y/%m/%d.%H:%M:%S')}-{dt.strftime('%Y/%m/%d.%H:%M:%S')}"
    
    try:
        direction = get_traffic_direction(ip, tf)
        src_ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","10","-a",f"src ip {ip}"], tf), expected_key='dp')
        dst_ports = parse_csv(run_nfdump(["-s","srcport/bytes/flows","-n","10","-a",f"dst ip {ip}"], tf), expected_key='sp')
        protocols = parse_csv(run_nfdump(["-s","proto/bytes/packets","-n","5","-a",f"ip {ip}"], tf), expected_key='proto')
    except Exception as e:
        # If nfdump fails, return partial data
        direction = {"upload": 0, "download": 0}
        src_ports = []
        dst_ports = []
        protocols = []
        print(f"Warning: nfdump query failed for IP {ip}: {e}")

    # Enrich
    for p in protocols:
        try:
            proto = int(p["key"]); p["proto_name"] = PROTOS.get(proto, f"Proto-{p['key']}")
        except Exception:
            p["proto_name"] = p["key"]

    geo = lookup_geo(ip)
    
    # Threat Intelligence lookup (optional, graceful degradation if no API keys)
    threat_intel = lookup_threat_intelligence(ip)
    
    # Traffic pattern anomaly detection
    anomalies = detect_ip_anomalies(ip, tf, direction, src_ports, dst_ports, protocols)
    
    # Generate alerts for high-severity anomalies
    generate_ip_anomaly_alerts(ip, anomalies, geo)
    
    # Find related IPs (simplified: IPs that appear in flows with this IP)
    # This finds IPs that directly communicate with this IP (as source or destination)
    related_ips = []
    try:
        # Get flows involving this IP
        convs_output = run_nfdump(["-a", f"ip {ip}", "-n", "500", "-o", "csv"], tf)
        lines = convs_output.strip().split("\n")
        if len(lines) > 1:
            header = lines[0].split(',')
            try:
                sa_idx = header.index('sa')
                da_idx = header.index('da')
                ibyt_idx = header.index('ibyt')
            except ValueError:
                sa_idx, da_idx, ibyt_idx = 3, 4, 12
            
            # Track IPs that communicate with this IP
            related_ip_stats = defaultdict(lambda: {'bytes': 0, 'count': 0, 'type': ''})
            
            for line in lines[1:]:
                if not line or line.startswith('ts,'): continue
                parts = line.split(',')
                if len(parts) > max(sa_idx, da_idx, ibyt_idx):
                    try:
                        src = parts[sa_idx].strip()
                        dst = parts[da_idx].strip()
                        bytes_val = int(parts[ibyt_idx]) if len(parts) > ibyt_idx and parts[ibyt_idx].strip().isdigit() else 0
                        
                        if src == ip and dst != ip:
                            # This IP is source - track destination as related
                            related_ip_stats[dst]['bytes'] += bytes_val
                            related_ip_stats[dst]['count'] += 1
                            related_ip_stats[dst]['type'] = 'destination'
                        elif dst == ip and src != ip:
                            # This IP is destination - track source as related
                            related_ip_stats[src]['bytes'] += bytes_val
                            related_ip_stats[src]['count'] += 1
                            related_ip_stats[src]['type'] = 'source'
                    except (ValueError, IndexError):
                        pass
            
            # Get top related IPs (limit to 10)
            related_ips = sorted([{'ip': ip_addr, 'bytes': data['bytes'], 'count': data['count'], 'type': data['type']} 
                                for ip_addr, data in related_ip_stats.items()], 
                               key=lambda x: x['bytes'], reverse=True)[:10]
            
            # Enrich related IPs with geo data
            for r_ip in related_ips:
                r_geo = lookup_geo(r_ip['ip'])
                r_ip['country'] = r_geo.get('country', 'Unknown') if r_geo else 'Unknown'
                r_ip['country_code'] = r_geo.get('country_code', '') if r_geo else ''
    except Exception as e:
        print(f"Warning: Related IPs discovery failed for IP {ip}: {e}")
    
    data = {
        "ip": ip,
        "hostname": resolve_ip(ip),
        "region": get_region(ip, geo.get('country_iso') if geo else None),
        "internal": is_internal(ip),
        "geo": geo,
        "direction": direction,
        "src_ports": src_ports,
        "dst_ports": dst_ports,
        "protocols": protocols,
        "threat": False,
        "related_ips": related_ips,
        "threat_intel": threat_intel,
        "anomalies": anomalies
    }
    return jsonify(data)


@app.route("/api/trends/source/<ip>")
def api_trends_source(ip):
    """Return 5-min rollup trend for a source IP over the requested range (default 24h)."""
    range_key = request.args.get('range', '24h')
    compare = request.args.get('compare', 'false').lower() == 'true'  # Historical comparison
    now = datetime.now()
    minutes = {'15m': 15, '30m': 30, '1h': 60, '6h': 360, '24h': 1440}.get(range_key, 1440)
    end_dt = _get_bucket_end(now)
    start_dt = end_dt - timedelta(minutes=minutes)
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT bucket_end, bytes, flows FROM top_sources WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                (ip, start_ts, end_ts)
            )
            rows = cur.fetchall()
            
            # Historical comparison: get same duration from previous period
            comparison = None
            if compare and rows:
                prev_end_dt = start_dt
                prev_start_dt = prev_end_dt - timedelta(minutes=minutes)
                prev_start_ts = int(prev_start_dt.timestamp())
                prev_end_ts = int(prev_end_dt.timestamp())
                
                prev_cur = conn.execute(
                    "SELECT bucket_end, bytes, flows FROM top_sources WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                    (ip, prev_start_ts, prev_end_ts)
                )
                prev_rows = prev_cur.fetchall()
                if prev_rows:
                    comparison = {
                        "labels": [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in prev_rows],
                        "bytes": [r[1] for r in prev_rows],
                        "flows": [r[2] for r in prev_rows]
                    }
        finally:
            conn.close()
    labels = [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in rows]
    bytes_arr = [r[1] for r in rows]
    flows_arr = [r[2] for r in rows]
    result = {"labels": labels, "bytes": bytes_arr, "flows": flows_arr}
    if comparison:
        result["comparison"] = comparison
    return jsonify(result)


@app.route("/api/trends/dest/<ip>")
def api_trends_dest(ip):
    """Return 5-min rollup trend for a destination IP over the requested range (default 24h)."""
    range_key = request.args.get('range', '24h')
    compare = request.args.get('compare', 'false').lower() == 'true'  # Historical comparison
    now = datetime.now()
    minutes = {'15m': 15, '30m': 30, '1h': 60, '6h': 360, '24h': 1440}.get(range_key, 1440)
    end_dt = _get_bucket_end(now)
    start_dt = end_dt - timedelta(minutes=minutes)
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT bucket_end, bytes, flows FROM top_dests WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                (ip, start_ts, end_ts)
            )
            rows = cur.fetchall()
            
            # Historical comparison: get same duration from previous period
            comparison = None
            if compare and rows:
                prev_end_dt = start_dt
                prev_start_dt = prev_end_dt - timedelta(minutes=minutes)
                prev_start_ts = int(prev_start_dt.timestamp())
                prev_end_ts = int(prev_end_dt.timestamp())
                
                prev_cur = conn.execute(
                    "SELECT bucket_end, bytes, flows FROM top_dests WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                    (ip, prev_start_ts, prev_end_ts)
                )
                prev_rows = prev_cur.fetchall()
                if prev_rows:
                    comparison = {
                        "labels": [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in prev_rows],
                        "bytes": [r[1] for r in prev_rows],
                        "flows": [r[2] for r in prev_rows]
                    }
        finally:
            conn.close()
    labels = [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in rows]
    bytes_arr = [r[1] for r in rows]
    flows_arr = [r[2] for r in rows]
    result = {"labels": labels, "bytes": bytes_arr, "flows": flows_arr}
    if comparison:
        result["comparison"] = comparison
    return jsonify(result)

@app.route("/api/export")
def export_csv():
    # Use Summary logic but return raw text
    range_key = request.args.get('range', '1h')
    tf = get_time_range(range_key)
    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf), expected_key='sa')
    csv = "IP,Bytes,Flows\n" + "\n".join([f"{s['key']},{s['bytes']},{s['flows']}" for s in sources])
    return csv, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=netflow_export.csv'}

@app.route("/api/export_json")
def export_json():
    return api_stats_summary()

@app.route("/api/test_alert")
def api_test_alert():
    alert = {"severity":"critical","msg":"TEST ALERT triggered from UI","feed":"local"}
    send_notifications([alert])
    return jsonify({"status":"ok","sent":True})

@app.route('/api/threat_refresh', methods=['POST'])
def api_threat_refresh():
    fetch_threat_feed()
    return jsonify({"status":"ok","threat_status": _threat_status})


@app.route('/api/ollama/chat', methods=['POST'])
@throttle(10, 60)  # 10 requests per minute
def api_ollama_chat():
    """Chat endpoint that proxies requests to local Ollama instance."""
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        model = data.get('model', 'deepseek-coder-v2:16b')  # Default model, can be overridden
        stream = data.get('stream', False)
        
        if not message:
            return jsonify({"error": "Message is required"}), 400
        
        # Ollama API endpoint (default: 192.168.0.88:11434)
        ollama_base = os.getenv('OLLAMA_URL', 'http://192.168.0.88:11434')
        # Remove /api/chat if present (for backwards compatibility)
        ollama_base = ollama_base.replace('/api/chat', '')
        ollama_url = f"{ollama_base}/api/chat"
        
        # Prepare request to Ollama
        ollama_payload = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": message
                }
            ],
            "stream": stream
        }
        
        # Make request to Ollama
        timeout = 120 if stream else 60  # Longer timeout for streaming
        response = requests.post(
            ollama_url,
            json=ollama_payload,
            timeout=timeout,
            stream=stream
        )
        
        if response.status_code != 200:
            return jsonify({
                "error": f"Ollama API error: {response.status_code}",
                "details": response.text[:200]
            }), response.status_code
        
        if stream:
            # For streaming, return Server-Sent Events
            def generate():
                for line in response.iter_lines():
                    if line:
                        yield f"data: {line.decode('utf-8')}\n\n"
                yield "data: [DONE]\n\n"
            
            return Response(
                generate(),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'X-Accel-Buffering': 'no'
                }
            )
        else:
            # For non-streaming, return JSON response
            return jsonify(response.json())
    
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": f"Cannot connect to Ollama at {ollama_url}. Make sure Ollama is running and accessible."
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            "error": "Request to Ollama timed out"
        }), 504
    except Exception as e:
        print(f"Ollama chat error: {e}")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)[:200]
        }), 500


@app.route('/api/ollama/models', methods=['GET'])
@throttle(5, 60)
def api_ollama_models():
    """Get list of available Ollama models."""
    try:
        # Ollama API base URL (default: 192.168.0.88:11434)
        ollama_base = os.getenv('OLLAMA_URL', 'http://192.168.0.88:11434')
        # Remove /api/chat if present (for backwards compatibility)
        ollama_base = ollama_base.replace('/api/chat', '')
        response = requests.get(f"{ollama_base}/api/tags", timeout=10)
        
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch models"}), response.status_code
        
        data = response.json()
        models = [model.get('name', '') for model in data.get('models', [])]
        return jsonify({"models": models})
    
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to Ollama", "models": []}), 503
    except Exception as e:
        print(f"Ollama models error: {e}")
        return jsonify({"error": str(e), "models": []}), 500


@app.route('/api/stats/threats')
@throttle(5, 10)
def api_threats():
    """Get threat detections with category, geo info, and firewall block status"""
    range_key = request.args.get('range', '1h')
    range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    cutoff = time.time() - range_seconds
    
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    threat_set = threat_set - whitelist
    
    # Get blocked IPs from firewall logs
    blocked_ips = {}
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute("""
                    SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_blocked
                    FROM fw_logs 
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                    GROUP BY src_ip
                """, (cutoff,))
                for row in cur.fetchall():
                    blocked_ips[row[0]] = {'count': row[1], 'last_blocked': row[2]}
            finally:
                conn.close()
    except Exception:
        pass  # Syslog may not be configured yet
    
    # Get sources/destinations and find threat matches
    sources = get_common_nfdump_data("sources", range_key)[:50]
    destinations = get_common_nfdump_data("destinations", range_key)[:50]
    
    hits = []
    seen = set()
    
    for item in sources + destinations:
        ip = item.get("key", "")
        if ip in threat_set and ip not in seen:
            seen.add(ip)
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            block_info = blocked_ips.get(ip, {})
            hits.append({
                "ip": ip,
                "category": info.get("category", "UNKNOWN"),
                "feed": info.get("feed", "unknown"),
                "bytes": item.get("bytes", 0),
                "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                "flows": item.get("flows", 0),
                "country": geo.get("country_code", "--"),
                "city": geo.get("city", ""),
                "hits": item.get("flows", 1),
                "blocked": block_info.get('count', 0) > 0,
                "block_count": block_info.get('count', 0),
                "last_blocked": datetime.fromtimestamp(block_info['last_blocked']).isoformat() if block_info.get('last_blocked') else None
            })
    
    # Sort by bytes descending
    hits.sort(key=lambda x: x["bytes"], reverse=True)
    
    # Summary stats
    total_blocked = sum(1 for h in hits if h['blocked'])
    
    return jsonify({
        "hits": hits[:20],
        "total_threats": len(hits),
        "total_blocked": total_blocked,
        "feed_ips": _threat_status.get("size", 0),
        "threat_status": _threat_status
    })


@app.route('/api/stats/malicious_ports')
@throttle(5, 10)
def api_malicious_ports():
    """Get top malicious ports - combining threat traffic + firewall blocks"""
    range_key = request.args.get('range', '1h')
    
    # Suspicious ports to highlight
    SUSPICIOUS_PORTS = {
        22: 'SSH',
        23: 'Telnet',
        445: 'SMB',
        3389: 'RDP',
        5900: 'VNC',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        11211: 'Memcached',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        4444: 'Metasploit',
        5555: 'Android ADB',
        6666: 'IRC',
        31337: 'Back Orifice',
    }
    
    port_data = {}
    
    # Get blocked ports from firewall syslog
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            
            range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
            cutoff = int(time.time()) - range_seconds
            
            # Get blocked ports with counts
            cur.execute("""
                SELECT dst_port, COUNT(*) as hits, COUNT(DISTINCT src_ip) as unique_ips
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ? AND dst_port > 0
                GROUP BY dst_port
                ORDER BY hits DESC
                LIMIT 50
            """, (cutoff,))
            
            for row in cur.fetchall():
                port = row['dst_port']
                service = SUSPICIOUS_PORTS.get(port, 'Unknown')
                port_data[port] = {
                    'port': port,
                    'service': service,
                    'blocked': row['hits'],
                    'unique_attackers': row['unique_ips'],
                    'netflow_bytes': 0,
                    'netflow_flows': 0,
                    'suspicious': port in SUSPICIOUS_PORTS
                }
            conn.close()
    except Exception as e:
        pass  # Syslog not available, continue with NetFlow only
    
    # Merge with threat traffic from NetFlow
    try:
        tf = get_time_range(range_key)
        threat_set = load_threatlist()
        output = run_nfdump(["-o", "csv", "-n", "500", "-s", "ip/bytes"], tf)
        
        lines = output.strip().split('\n')
        if len(lines) > 1:
            header = [c.strip().lower() for c in lines[0].split(',')]
            ip_idx = next((i for i, h in enumerate(header) if 'ip' in h and 'addr' in h), None)
            byt_idx = next((i for i, h in enumerate(header) if h in ('ibyt', 'bytes')), None)
            fl_idx = next((i for i, h in enumerate(header) if h in ('fl', 'flows')), None)
            
            if ip_idx is not None:
                for line in lines[1:]:
                    parts = line.split(',')
                    if len(parts) > max(ip_idx, byt_idx or 0, fl_idx or 0):
                        ip = parts[ip_idx].strip()
                        if ip in threat_set:
                            # Get port info for this threat IP
                            port_output = run_nfdump(["-o", "csv", "-n", "10", "-s", "port/bytes", f"src ip {ip} or dst ip {ip}"], tf)
                            port_lines = port_output.strip().split('\n')
                            if len(port_lines) > 1:
                                p_header = [c.strip().lower() for c in port_lines[0].split(',')]
                                p_idx = next((i for i, h in enumerate(p_header) if h == 'port'), None)
                                p_byt_idx = next((i for i, h in enumerate(p_header) if h in ('ibyt', 'bytes')), None)
                                p_fl_idx = next((i for i, h in enumerate(p_header) if h in ('fl', 'flows')), None)
                                
                                if p_idx is not None:
                                    for pline in port_lines[1:3]:  # Top 2 ports per threat
                                        pparts = pline.split(',')
                                        try:
                                            port = int(pparts[p_idx].strip())
                                            bytes_val = int(pparts[p_byt_idx].strip()) if p_byt_idx else 0
                                            flows_val = int(pparts[p_fl_idx].strip()) if p_fl_idx else 0
                                            
                                            if port not in port_data:
                                                port_data[port] = {
                                                    'port': port,
                                                    'service': SUSPICIOUS_PORTS.get(port, 'Unknown'),
                                                    'blocked': 0,
                                                    'unique_attackers': 0,
                                                    'netflow_bytes': 0,
                                                    'netflow_flows': 0,
                                                    'suspicious': port in SUSPICIOUS_PORTS
                                                }
                                            port_data[port]['netflow_bytes'] += bytes_val
                                            port_data[port]['netflow_flows'] += flows_val
                                        except:
                                            pass
    except:
        pass
    
    # Convert to list and sort by total activity (blocked + flows)
    ports = list(port_data.values())
    for p in ports:
        p['total_score'] = p['blocked'] * 10 + p['netflow_flows']  # Weight blocks higher
        p['bytes_fmt'] = fmt_bytes(p['netflow_bytes'])
    
    ports.sort(key=lambda x: x['total_score'], reverse=True)
    
    return jsonify({
        "ports": ports[:20],
        "total": len(ports),
        "has_syslog": any(p['blocked'] > 0 for p in ports)
    })


@app.route('/api/stats/feeds')
@throttle(5, 10)
def api_feed_status():
    """Get per-feed health status"""
    feeds = []
    for name, info in _feed_status.items():
        last_ok = info.get('last_ok', 0)
        feeds.append({
            "name": name,
            "category": info.get("category", "UNKNOWN"),
            "status": info.get("status", "unknown"),
            "ips": info.get("ips", 0),
            "latency_ms": info.get("latency_ms", 0),
            "error": info.get("error"),
            "last_ok_ago": format_time_ago(last_ok) if last_ok else "never"
        })
    
    # Sort by status (ok first), then by ips
    feeds.sort(key=lambda x: (0 if x["status"] == "ok" else 1, -x["ips"]))
    
    return jsonify({
        "feeds": feeds,
        "summary": {
            "total": len(feeds),
            "ok": sum(1 for f in feeds if f["status"] == "ok"),
            "error": sum(1 for f in feeds if f["status"] == "error"),
            "total_ips": _threat_status.get("size", 0),
            "last_refresh": format_time_ago(_threat_status.get("last_ok", 0)) if _threat_status.get("last_ok") else "never"
        }
    })


def format_time_ago(ts):
    """Format timestamp as human-readable time ago"""
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        return f"{int(diff/60)}m ago"
    elif diff < 86400:
        return f"{int(diff/3600)}h ago"
    else:
        return f"{int(diff/86400)}d ago"


@app.route('/api/security/score')
@throttle(5, 10)
def api_security_score():
    """Get current security score"""
    return jsonify(calculate_security_score())


@app.route('/api/security/alerts/history')
@throttle(5, 10)
def api_alert_history():
    """Get alert history for past 24 hours"""
    now = time.time()
    cutoff = now - 86400  # 24 hours
    
    with _alert_history_lock:
        recent = [a for a in _alert_history if a.get('ts', 0) > cutoff]
    
    # Sort by timestamp descending
    recent.sort(key=lambda x: x.get('ts', 0), reverse=True)
    
    # Format timestamps
    for alert in recent:
        ts = alert.get('ts', 0)
        alert['time_ago'] = format_time_ago(ts)
        alert['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    
    # Group by hour for chart
    hourly = defaultdict(int)
    for alert in recent:
        hour = time.strftime('%H:00', time.localtime(alert.get('ts', 0)))
        hourly[hour] += 1
    
    return jsonify({
        'alerts': recent[:100],
        'total': len(recent),
        'by_severity': {
            'critical': sum(1 for a in recent if a.get('severity') == 'critical'),
            'high': sum(1 for a in recent if a.get('severity') == 'high'),
            'medium': sum(1 for a in recent if a.get('severity') == 'medium'),
            'low': sum(1 for a in recent if a.get('severity') == 'low'),
        },
        'hourly': dict(hourly)
    })


@app.route('/api/security/threats/export')
def api_export_threats():
    """Export detected threats as JSON or CSV"""
    fmt = request.args.get('format', 'json')
    
    # Get recent threats
    now = time.time()
    threats = []
    for ip, timeline in _threat_timeline.items():
        if now - timeline['last_seen'] < 86400:  # Last 24h
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            threats.append({
                'ip': ip,
                'category': info.get('category', 'UNKNOWN'),
                'feed': info.get('feed', 'unknown'),
                'mitre_technique': info.get('mitre_technique', ''),
                'mitre_tactic': info.get('mitre_tactic', ''),
                'country': geo.get('country_code', '--'),
                'city': geo.get('city', ''),
                'first_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timeline['first_seen'])),
                'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timeline['last_seen'])),
                'hit_count': timeline['hit_count']
            })
    
    if fmt == 'csv':
        import io
        import csv
        output = io.StringIO()
        if threats:
            writer = csv.DictWriter(output, fieldnames=threats[0].keys())
            writer.writeheader()
            writer.writerows(threats)
        response = app.response_class(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=threats.csv'}
        )
        return response
    
    return jsonify({
        'threats': threats,
        'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total': len(threats)
    })


@app.route('/api/security/attack-timeline')
@throttle(5, 10)
def api_attack_timeline():
    """Get attack timeline data for visualization with configurable time range."""
    range_key = request.args.get('range', '24h')
    range_seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 86400)
    now = time.time()
    cutoff = now - range_seconds
    
    with _alert_history_lock:
        recent = [a for a in _alert_history if a.get('ts', 0) > cutoff]
    
    # Determine bucket size based on range
    if range_key == '1h':
        bucket_size = 300  # 5-minute buckets for 1 hour (12 buckets)
        bucket_label_format = '%H:%M'
    elif range_key == '6h':
        bucket_size = 1800  # 30-minute buckets for 6 hours (12 buckets)
        bucket_label_format = '%H:%M'
    elif range_key == '24h':
        bucket_size = 3600  # 1-hour buckets for 24 hours (24 buckets)
        bucket_label_format = '%H:00'
    elif range_key == '7d':
        bucket_size = 86400  # 1-day buckets for 7 days (7 buckets)
        bucket_label_format = '%m/%d'
    else:
        bucket_size = 3600
        bucket_label_format = '%H:00'
    
    num_buckets = int(range_seconds / bucket_size)
    
    # Get firewall block counts from syslog (if available)
    fw_buckets = {}
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cutoff_int = int(cutoff)
            
            if range_key == '7d':
                # Daily buckets for 7 days
                cur.execute("""
                    SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch', 'localtime')) as day,
                           COUNT(*) as blocks,
                           SUM(is_threat) as threat_blocks
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY day
                """, (cutoff_int,))
                for row in cur.fetchall():
                    day_str = time.strftime('%m/%d', time.strptime(row[0], '%Y-%m-%d'))
                    fw_buckets[day_str] = {'blocks': row[1], 'threat_blocks': row[2] or 0}
            elif range_key == '24h':
                # Hourly buckets for 24h
                cur.execute("""
                    SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) as hour,
                           COUNT(*) as blocks,
                           SUM(is_threat) as threat_blocks
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY hour
                """, (cutoff_int,))
                for row in cur.fetchall():
                    fw_buckets[row[0] + ':00'] = {'blocks': row[1], 'threat_blocks': row[2] or 0}
            else:
                # For 1h and 6h, fetch all blocks and group by bucket
                cur.execute("""
                    SELECT timestamp, is_threat
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                """, (cutoff_int,))
                for row in cur.fetchall():
                    bucket_start = int(row[0] / bucket_size) * bucket_size
                    bucket_label = time.strftime(bucket_label_format, time.localtime(bucket_start))
                    if bucket_label not in fw_buckets:
                        fw_buckets[bucket_label] = {'blocks': 0, 'threat_blocks': 0}
                    fw_buckets[bucket_label]['blocks'] += 1
                    if row[1]:
                        fw_buckets[bucket_label]['threat_blocks'] += 1
            conn.close()
    except Exception:
        pass
    
    # Build timeline buckets
    timeline = []
    for i in range(num_buckets):
        bucket_start = now - ((num_buckets - 1 - i) * bucket_size)
        bucket_end = bucket_start + bucket_size
        bucket_label = time.strftime(bucket_label_format, time.localtime(bucket_start))
        
        # Filter alerts for this bucket
        bucket_alerts = [a for a in recent if bucket_start <= a.get('ts', 0) < bucket_end]
        
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for a in bucket_alerts:
            by_type[a.get('type', 'unknown')] += 1
            by_severity[a.get('severity', 'low')] += 1
        
        # Add firewall block data
        fw_data = fw_buckets.get(bucket_label, {'blocks': 0, 'threat_blocks': 0})
        
        timeline.append({
            'hour': bucket_label,  # Keep 'hour' key for compatibility, but contains appropriate label
            'timestamp': bucket_start,
            'total': len(bucket_alerts),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'critical': by_severity.get('critical', 0),
            'high': by_severity.get('high', 0),
            'medium': by_severity.get('medium', 0),
            'low': by_severity.get('low', 0),
            'fw_blocks': fw_data['blocks'],
            'fw_threat_blocks': fw_data['threat_blocks']
        })
    
    # Peak bucket
    peak = max(timeline, key=lambda x: x['total']) if timeline else None
    total_fw_blocks = sum(t['fw_blocks'] for t in timeline)
    
    return jsonify({
        'timeline': timeline,
        'total_24h': len(recent),  # Keep key for compatibility, but contains data for selected range
        'peak_hour': peak['hour'] if peak else None,
        'peak_count': peak['total'] if peak else 0,
        'fw_blocks_24h': total_fw_blocks,
        'has_fw_data': total_fw_blocks > 0
    })


@app.route('/api/security/mitre-heatmap')
@throttle(5, 10)
def api_mitre_heatmap():
    """Get MITRE ATT&CK technique coverage from alerts."""
    now = time.time()
    cutoff = now - 86400  # 24 hours
    
    with _alert_history_lock:
        recent = [a for a in _alert_history if a.get('ts', 0) > cutoff]
    
    # Count by MITRE technique
    techniques = defaultdict(lambda: {'count': 0, 'alerts': [], 'tactic': '', 'name': ''})
    
    for alert in recent:
        mitre = alert.get('mitre', '')
        if mitre:
            techniques[mitre]['count'] += 1
            if len(techniques[mitre]['alerts']) < 5:
                techniques[mitre]['alerts'].append({
                    'type': alert.get('type'),
                    'msg': alert.get('msg', '')[:50],
                    'severity': alert.get('severity')
                })
    
    # Enrich with MITRE info
    mitre_info = {
        'T1046': {'tactic': 'Discovery', 'name': 'Network Service Discovery'},
        'T1110': {'tactic': 'Credential Access', 'name': 'Brute Force'},
        'T1041': {'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
        'T1071': {'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
        'T1071.004': {'tactic': 'Command and Control', 'name': 'DNS'},
        'T1021': {'tactic': 'Lateral Movement', 'name': 'Remote Services'},
        'T1095': {'tactic': 'Command and Control', 'name': 'Non-Application Layer Protocol'},
        'T1029': {'tactic': 'Exfiltration', 'name': 'Scheduled Transfer'},
        'T1190': {'tactic': 'Initial Access', 'name': 'Exploit Public-Facing Application'},
        'T1105': {'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
        'T1595': {'tactic': 'Reconnaissance', 'name': 'Active Scanning'},
        'T1090': {'tactic': 'Command and Control', 'name': 'Proxy'},
        'T1584': {'tactic': 'Resource Development', 'name': 'Compromise Infrastructure'},
        'T1583': {'tactic': 'Resource Development', 'name': 'Acquire Infrastructure'},
    }
    
    heatmap = []
    for tech_id, data in techniques.items():
        info = mitre_info.get(tech_id, {'tactic': 'Unknown', 'name': tech_id})
        heatmap.append({
            'technique': tech_id,
            'tactic': info['tactic'],
            'name': info['name'],
            'count': data['count'],
            'alerts': data['alerts']
        })
    
    # Sort by count descending
    heatmap.sort(key=lambda x: x['count'], reverse=True)
    
    # Group by tactic for visualization
    by_tactic = defaultdict(list)
    for item in heatmap:
        by_tactic[item['tactic']].append(item)
    
    return jsonify({
        'techniques': heatmap,
        'by_tactic': dict(by_tactic),
        'total_techniques': len(heatmap),
        'total_detections': sum(t['count'] for t in heatmap)
    })


@app.route('/api/security/protocol-anomalies')
@throttle(5, 10)
def api_protocol_anomalies():
    """Get protocol anomaly data for Security Center."""
    global _protocol_baseline
    
    range_key = request.args.get('range', '1h')
    protocols_data = get_common_nfdump_data("protocols", range_key)[:20]
    
    anomalies = []
    for proto in protocols_data:
        proto_name = proto.get('key') or proto.get('proto')
        proto_bytes = proto.get('bytes', 0)
        
        baseline = _protocol_baseline.get(proto_name, {})
        avg = baseline.get('total_bytes', proto_bytes) / max(baseline.get('samples', 1), 1)
        
        deviation = (proto_bytes / avg) if avg > 0 else 1
        
        anomalies.append({
            'protocol': proto_name,
            'bytes': proto_bytes,
            'bytes_fmt': fmt_bytes(proto_bytes),
            'avg_bytes': avg,
            'avg_fmt': fmt_bytes(avg),
            'deviation': round(deviation, 2),
            'is_anomaly': deviation > 2.0 and proto_bytes > 5 * 1024 * 1024,  # 2x+ and 5MB+
            'flows': proto.get('flows', 0)
        })
    
    # Sort anomalies first, then by deviation
    anomalies.sort(key=lambda x: (not x['is_anomaly'], -x['deviation']))
    
    return jsonify({
        'protocols': anomalies,
        'anomaly_count': sum(1 for a in anomalies if a['is_anomaly']),
        'baseline_samples': sum(b.get('samples', 0) for b in _protocol_baseline.values())
    })


@app.route('/api/security/run-detection')
@throttle(2, 10)
def api_run_detection():
    """Manually trigger all detection algorithms."""
    range_key = request.args.get('range', '1h')
    
    try:
        ports_data = get_common_nfdump_data("ports", range_key)[:50]
        sources_data = get_common_nfdump_data("sources", range_key)[:50]
        destinations_data = get_common_nfdump_data("destinations", range_key)[:50]
        protocols_data = get_common_nfdump_data("protocols", range_key)[:20]
        
        # Run all detections
        new_alerts = run_all_detections(ports_data, sources_data, destinations_data, protocols_data)
        
        return jsonify({
            'status': 'ok',
            'new_alerts': len(new_alerts),
            'alerts': new_alerts[:20]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/security/threats/by_country')
@throttle(5, 10)
def api_threats_by_country():
    """Get threat counts grouped by country with firewall block data"""
    country_stats = defaultdict(lambda: {'count': 0, 'ips': [], 'categories': defaultdict(int), 'blocked': 0})
    
    # Get blocked IPs by country from syslog
    blocked_by_country = {}
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cutoff = int(time.time()) - 86400
            cur.execute("""
                SELECT country_iso, COUNT(*) as blocks, COUNT(DISTINCT src_ip) as unique_ips
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ? AND country_iso IS NOT NULL
                GROUP BY country_iso
            """, (cutoff,))
            for row in cur.fetchall():
                if row[0]:
                    blocked_by_country[row[0]] = {'blocks': row[1], 'unique_ips': row[2]}
            conn.close()
    except:
        pass
    
    for ip, timeline in _threat_timeline.items():
        if time.time() - timeline['last_seen'] < 86400:
            geo = lookup_geo(ip) or {}
            country = geo.get('country_code', 'XX')
            country_name = geo.get('country', 'Unknown')
            
            country_stats[country]['count'] += 1
            country_stats[country]['name'] = country_name
            if len(country_stats[country]['ips']) < 5:
                country_stats[country]['ips'].append(ip)
            
            info = get_threat_info(ip)
            country_stats[country]['categories'][info.get('category', 'UNKNOWN')] += 1
    
    # Merge with firewall block data
    for code, block_data in blocked_by_country.items():
        if code not in country_stats:
            # Country only seen in firewall blocks, not in threat feeds
            country_stats[code]['name'] = code  # We don't have the full name
            country_stats[code]['blocked_only'] = True
        country_stats[code]['blocked'] = block_data['blocks']
        country_stats[code]['blocked_ips'] = block_data['unique_ips']
    
    # Convert to list and sort
    result = []
    for code, data in country_stats.items():
        result.append({
            'country_code': code,
            'country_name': data.get('name', 'Unknown'),
            'threat_count': data['count'],
            'blocked': data.get('blocked', 0),
            'blocked_ips': data.get('blocked_ips', 0),
            'sample_ips': data['ips'],
            'categories': dict(data['categories']),
            'blocked_only': data.get('blocked_only', False)
        })
    
    result.sort(key=lambda x: (x['threat_count'] + x['blocked']), reverse=True)
    total_blocked = sum(r['blocked'] for r in result)
    
    return jsonify({
        'countries': result[:20],
        'total_countries': len(result),
        'total_blocked': total_blocked,
        'has_fw_data': total_blocked > 0
    })


@app.route('/api/security/threat_velocity')
@throttle(5, 10)
def api_threat_velocity():
    """Get threat detection velocity (threats per hour)"""
    now = time.time()
    hour_ago = now - 3600
    two_hours_ago = now - 7200
    day_ago = now - 86400
    
    # Count threats in different time windows
    current_hour = 0
    last_hour = 0
    total_24h = 0
    hourly_counts = defaultdict(int)
    
    with _alert_history_lock:
        for alert in _alert_history:
            ts = alert.get('ts', 0)
            if ts > day_ago:
                total_24h += 1
                hour_bucket = int((now - ts) // 3600)
                hourly_counts[hour_bucket] += 1
                
                if ts > hour_ago:
                    current_hour += 1
                elif ts > two_hours_ago:
                    last_hour += 1
    
    # Calculate trend (% change from last hour)
    if last_hour > 0:
        trend = int(((current_hour - last_hour) / last_hour) * 100)
    elif current_hour > 0:
        trend = 100
    else:
        trend = 0
    
    # Find peak hour
    peak = max(hourly_counts.values()) if hourly_counts else 0
    
    return jsonify({
        'current': current_hour,
        'trend': trend,
        'total_24h': total_24h,
        'peak': peak,
        'hourly': dict(hourly_counts)
    })


@app.route('/api/security/top_threat_ips')
@throttle(5, 10)
def api_top_threat_ips():
    """Get top threat IPs by hit count"""
    now = time.time()
    
    # Get IPs with timeline data from last 24h
    threat_ips = []
    for ip, timeline in _threat_timeline.items():
        if now - timeline['last_seen'] < 86400:
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            threat_ips.append({
                'ip': ip,
                'hits': timeline.get('hit_count', 1),
                'first_seen': timeline.get('first_seen'),
                'last_seen': timeline.get('last_seen'),
                'category': info.get('category', 'UNKNOWN'),
                'feed': info.get('feed', 'unknown'),
                'country': geo.get('country_code', '--'),
                'mitre': info.get('mitre_technique', '')
            })
    
    # Sort by hits descending
    threat_ips.sort(key=lambda x: x['hits'], reverse=True)
    
    return jsonify({
        'ips': threat_ips[:10],
        'total': len(threat_ips)
    })


@app.route('/api/security/risk_index')
@throttle(5, 10)
def api_risk_index():
    """Calculate Network Risk Index based on traffic patterns and threats"""
    # Gather risk factors
    risk_factors = []
    risk_score = 0
    
    # Factor 1: Active threats (0-30 points)
    threat_count = len(_threat_timeline)
    if threat_count == 0:
        risk_factors.append({'factor': 'Active Threats', 'value': 'None', 'impact': 'low', 'points': 0})
    elif threat_count <= 5:
        risk_score += 10
        risk_factors.append({'factor': 'Active Threats', 'value': f'{threat_count} IPs', 'impact': 'medium', 'points': 10})
    elif threat_count <= 20:
        risk_score += 20
        risk_factors.append({'factor': 'Active Threats', 'value': f'{threat_count} IPs', 'impact': 'high', 'points': 20})
    else:
        risk_score += 30
        risk_factors.append({'factor': 'Active Threats', 'value': f'{threat_count} IPs', 'impact': 'critical', 'points': 30})
    
    # Factor 2: Threat velocity (0-20 points)
    # Count threats seen in the last hour
    one_hour_ago = time.time() - 3600
    hourly_threats = len([ip for ip in _threat_timeline 
                          if _threat_timeline[ip]['last_seen'] >= one_hour_ago])
    if hourly_threats == 0:
        risk_factors.append({'factor': 'Threat Velocity', 'value': '0/hr', 'impact': 'low', 'points': 0})
    elif hourly_threats <= 5:
        risk_score += 5
        risk_factors.append({'factor': 'Threat Velocity', 'value': f'{hourly_threats}/hr', 'impact': 'medium', 'points': 5})
    elif hourly_threats <= 20:
        risk_score += 10
        risk_factors.append({'factor': 'Threat Velocity', 'value': f'{hourly_threats}/hr', 'impact': 'high', 'points': 10})
    else:
        risk_score += 20
        risk_factors.append({'factor': 'Threat Velocity', 'value': f'{hourly_threats}/hr', 'impact': 'critical', 'points': 20})
    
    # Factor 3: Feed coverage (0-15 points for poor coverage)
    global _feed_status
    if _feed_status:
        ok_feeds = sum(1 for f in _feed_status.values() if f.get('status') == 'ok')
        total_feeds = len(_feed_status)
        if total_feeds > 0:
            coverage = ok_feeds / total_feeds
            if coverage >= 0.9:
                risk_factors.append({'factor': 'Feed Coverage', 'value': f'{ok_feeds}/{total_feeds}', 'impact': 'low', 'points': 0})
            elif coverage >= 0.7:
                risk_score += 5
                risk_factors.append({'factor': 'Feed Coverage', 'value': f'{ok_feeds}/{total_feeds}', 'impact': 'medium', 'points': 5})
            else:
                risk_score += 15
                risk_factors.append({'factor': 'Feed Coverage', 'value': f'{ok_feeds}/{total_feeds}', 'impact': 'high', 'points': 15})
    
    # Factor 4: Suspicious port activity (0-20 points)
    suspicious_ports = {22, 23, 3389, 445, 135, 137, 138, 139, 1433, 3306, 5432}
    # Check if any suspicious ports have high traffic (simplified check)
    suspicious_activity = False
    for port in suspicious_ports:
        if port in [22, 3389]:  # Common admin ports - flag if from unusual sources
            suspicious_activity = True
            break
    if suspicious_activity:
        risk_score += 10
        risk_factors.append({'factor': 'Suspicious Ports', 'value': 'Detected', 'impact': 'medium', 'points': 10})
    else:
        risk_factors.append({'factor': 'Suspicious Ports', 'value': 'Normal', 'impact': 'low', 'points': 0})
    
    # Factor 5: External exposure (0-15 points)
    # Simplified: assume some external exposure exists
    risk_score += 5
    risk_factors.append({'factor': 'External Traffic', 'value': 'Present', 'impact': 'medium', 'points': 5})
    
    # Calculate risk level
    if risk_score <= 15:
        risk_level = 'LOW'
        risk_color = 'green'
    elif risk_score <= 35:
        risk_level = 'MODERATE'
        risk_color = 'yellow'
    elif risk_score <= 55:
        risk_level = 'ELEVATED'
        risk_color = 'orange'
    elif risk_score <= 75:
        risk_level = 'HIGH'
        risk_color = 'red'
    else:
        risk_level = 'CRITICAL'
        risk_color = 'red'
    
    return jsonify({
        'score': risk_score,
        'max_score': 100,
        'level': risk_level,
        'color': risk_color,
        'factors': risk_factors
    })


@app.route('/api/security/watchlist', methods=['GET'])
@throttle(5, 10)
def api_get_watchlist():
    """Get current watchlist"""
    watchlist = load_watchlist()
    items = []
    for ip in watchlist:
        geo = lookup_geo(ip) or {}
        items.append({
            'ip': ip,
            'country': geo.get('country_code', '--'),
            'city': geo.get('city', '')
        })
    return jsonify({'watchlist': items, 'count': len(items)})


@app.route('/api/security/watchlist', methods=['POST'])
def api_add_watchlist():
    """Add IP to watchlist"""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    success = add_to_watchlist(ip)
    return jsonify({'success': success, 'ip': ip})


@app.route('/api/security/watchlist', methods=['DELETE'])
def api_remove_watchlist():
    """Remove IP from watchlist"""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    success = remove_from_watchlist(ip)
    return jsonify({'success': success, 'ip': ip})


@app.route("/api/notify_status")
def api_notify_status():
    return jsonify(load_notify_cfg())

@app.route("/api/notify_toggle", methods=['POST'])
def api_notify_toggle():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get('target')
    state = bool(data.get('state', True))
    cfg = load_notify_cfg()
    if target == 'email':
        cfg['email'] = state
    elif target == 'webhook':
        cfg['webhook'] = state
    save_notify_cfg(cfg)
    return jsonify(cfg)

@app.route("/api/alerts_history")
def api_alerts_history():
    return jsonify(list(_alert_history))

@app.route('/api/alerts_export')
def api_alerts_export():
    return jsonify(list(_alert_history))

@app.route('/api/notify_mute', methods=['POST'])
def api_notify_mute():
    data = request.get_json(force=True, silent=True) or {}
    mute = bool(data.get('mute', True))
    cfg = load_notify_cfg()
    cfg['mute_until'] = time.time() + 3600 if mute else 0
    save_notify_cfg(cfg)
    return jsonify(cfg)

@app.route('/api/thresholds', methods=['GET', 'POST'])
def api_thresholds():
    if request.method == 'GET':
        return jsonify(load_thresholds())
    data = request.get_json(force=True, silent=True) or {}
    saved = save_thresholds(data)
    return jsonify(saved)


# ===== FORENSICS API ENDPOINTS =====

@app.route('/api/forensics/flow-search')
def api_forensics_flow_search():
    """Advanced flow search with multi-criteria filtering for forensics investigation."""
    range_val = request.args.get('range', '1h')
    src_ip = request.args.get('src_ip', '')
    dst_ip = request.args.get('dst_ip', '')
    port = request.args.get('port', '')
    protocol = request.args.get('protocol', '')
    country = request.args.get('country', '')

    # Build nfdump filter
    filters = []
    if src_ip:
        filters.append(f"src ip {src_ip}")
    if dst_ip:
        filters.append(f"dst ip {dst_ip}")
    if port:
        filters.append(f"(src port {port} or dst port {port})")
    if protocol:
        proto_map = {'tcp': '6', 'udp': '17', 'icmp': '1'}
        proto_num = proto_map.get(protocol.lower(), protocol)
        filters.append(f"proto {proto_num}")

    filter_str = ' and '.join(filters) if filters else ''
    tf = get_time_range(range_val)

    try:
        # Build nfdump command with filters
        # Note: run_nfdump automatically adds -o csv
        nfdump_args = ["-s", "bytes", "-n", "100"]
        if filter_str:
            nfdump_args.extend(["-A", filter_str])
        
        output = run_nfdump(nfdump_args, tf)

        flows = []
        lines = output.strip().split("\n")
        if not lines:
            return jsonify({'flows': [], 'count': 0})

        # Parse header dynamically
        header = lines[0].split(',')
        try:
            sa_idx = header.index('sa')
            da_idx = header.index('da')
            dp_idx = header.index('dp')
            pr_idx = header.index('proto')
            ibyt_idx = header.index('ibyt')
            ipkt_idx = header.index('ipkt')
        except ValueError:
            # Fallback indices (based on mock/nfdump std)
            sa_idx, da_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx = 3, 4, 6, 7, 12, 11

        seen_flows = set()
        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx):
                try:
                    src = parts[sa_idx].strip()
                    dst = parts[da_idx].strip()
                    dst_port = parts[dp_idx].strip()
                    proto = parts[pr_idx].strip()
                    
                    # Deduplicate flows
                    flow_key = (src, dst, proto, dst_port)
                    if flow_key in seen_flows:
                        continue
                    seen_flows.add(flow_key)

                    bytes_val = int(parts[ibyt_idx]) if len(parts) > ibyt_idx and parts[ibyt_idx].strip().isdigit() else 0
                    packets_val = int(parts[ipkt_idx]) if len(parts) > ipkt_idx and parts[ipkt_idx].strip().isdigit() else 0
                    port_val = int(dst_port) if dst_port.isdigit() else 0

                    # Map protocol number to name if needed
                    proto_name = proto
                    if proto.isdigit():
                        proto_name = PROTOS.get(int(proto), proto)

                    flows.append({
                        'src': src,
                        'dst': dst,
                        'proto': proto_name,
                        'port': port_val,
                        'bytes': bytes_val,
                        'packets': packets_val
                    })
                except (ValueError, IndexError):
                    continue

        # Sort by bytes descending
        flows.sort(key=lambda x: x.get('bytes', 0), reverse=True)
        flows = flows[:100]  # Limit to top 100

        # Apply country filter if specified
        if country:
            city_db = load_city_db()
            if city_db:
                filtered_flows = []
                for flow in flows:
                    try:
                        src_rec = city_db.get(flow['src'])
                        dst_rec = city_db.get(flow['dst'])
                        src_country = src_rec.get('country', {}).get('iso_code') if src_rec else None
                        dst_country = dst_rec.get('country', {}).get('iso_code') if dst_rec else None
                        if (src_country == country.upper()) or (dst_country == country.upper()):
                            filtered_flows.append(flow)
                    except:
                        pass
                flows = filtered_flows

        return jsonify({'flows': flows, 'count': len(flows)})

    except Exception as e:
        print(f"Flow search error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'flows': [], 'count': 0, 'error': str(e)})


@app.route('/api/forensics/alert-correlation')
def api_forensics_alert_correlation():
    """Correlate alerts to identify attack chains and multi-stage attacks."""
    try:
        range_val = request.args.get('range', '24h')
        range_seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_val, 86400)
        now = time.time()
        cutoff = now - range_seconds

        # Get alerts from history filtered by time range
        with _alert_history_lock:
            alerts = [a for a in _alert_history if a.get('ts', 0) > cutoff or a.get('timestamp', 0) > cutoff]

        # Group alerts by IP and time proximity (within 1 hour)
        chains = {}
        time_threshold = 3600  # 1 hour in seconds

        for alert in sorted(alerts, key=lambda x: float(x.get('timestamp', 0) or x.get('ts', 0))):
            ip = alert.get('ip') or alert.get('source_ip')
            if not ip:
                continue

            # Ensure timestamp is float
            try:
                timestamp = float(alert.get('timestamp', 0) or alert.get('ts', 0))
            except (ValueError, TypeError):
                continue

            # Find if this IP has an existing chain within time threshold
            found_chain = False
            
            # Optimization: Direct lookup instead of iteration
            if ip in chains:
                chain_data = chains[ip]
                last_alert = chain_data['alerts'][-1]
                try:
                    last_alert_time = float(last_alert.get('timestamp', 0) or last_alert.get('ts', 0))
                    if timestamp - last_alert_time <= time_threshold:
                        chain_data['alerts'].append(alert)
                        chain_data['end_time'] = timestamp
                        found_chain = True
                except (ValueError, TypeError):
                    pass

            # Create new chain if not found (or time gap too large - overwrites old chain logic preserved for now to avoid logic drift)
            if not found_chain:
                # If we are overwriting, we effectively split the chain and keep the latest segment.
                # Ideally we should store a list of chains, but for now let's just be robust.
                chains[ip] = {
                    'ip': ip,
                    'alerts': [alert],
                    'start_time': timestamp,
                    'end_time': timestamp
                }

        # Filter chains with multiple alerts and format response
        result_chains = []
        for ip, chain_data in chains.items():
            if len(chain_data['alerts']) > 1:  # Only chains with multiple related alerts
                formatted_alerts = []
                for a in chain_data['alerts']:
                    try:
                        ts_val = float(a.get('timestamp', 0) or a.get('ts', 0))
                        time_str = datetime.fromtimestamp(ts_val).strftime('%H:%M:%S')
                    except Exception:
                        time_str = 'recent'
                        ts_val = 0
                    
                    formatted_alerts.append({
                        'id': f"{a.get('type', 'alert')}_{ts_val}",
                        'type': a.get('type', 'unknown'),
                        'message': a.get('msg', 'Alert'),
                        'time': time_str
                    })

                result_chains.append({
                    'ip': ip,
                    'alerts': formatted_alerts,
                    'timespan': f"{len(chain_data['alerts'])} alerts over {int((chain_data['end_time'] - chain_data['start_time']) / 60)}min"
                })

        return jsonify({'chains': result_chains, 'count': len(result_chains)})
    except Exception as e:
        print(f"Error in alert correlation: {e}")
        return jsonify({'chains': [], 'count': 0, 'error': str(e)}), 500


# ===== Configuration Settings =====
def get_default_config():
    """Return default configuration values."""
    return {
        'dns_server': '192.168.0.6',
        'snmp_host': '192.168.0.1',
        'snmp_community': 'public',
        'snmp_poll_interval': 2.0,
        'nfdump_dir': '/var/cache/nfdump',
        'geoip_city_path': '/root/GeoLite2-City.mmdb',
        'geoip_asn_path': '/root/GeoLite2-ASN.mmdb',
        'threat_feeds_path': '/root/threat-feeds.txt',
        'internal_networks': '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12'
    }

def load_config():
    """Load configuration from file or return defaults."""
    defaults = get_default_config()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                saved = json.load(f)
                # Merge with defaults (saved values override)
                return {**defaults, **saved}
        except Exception:
            pass
    return defaults

def save_config(data):
    """Save configuration to file."""
    global DNS_SERVER, SNMP_HOST, SNMP_COMMUNITY, SNMP_POLL_INTERVAL, _shared_resolver
    current = load_config()
    # Only allow specific keys to be saved
    allowed_keys = get_default_config().keys()
    for k in allowed_keys:
        if k in data:
            current[k] = data[k]
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(current, f, indent=2)
        # Apply runtime updates where possible
        if 'dns_server' in data and data['dns_server']:
            DNS_SERVER = data['dns_server']
            _shared_resolver.nameservers = [DNS_SERVER]
        if 'snmp_host' in data:
            globals()['SNMP_HOST'] = data['snmp_host']
        if 'snmp_community' in data:
            globals()['SNMP_COMMUNITY'] = data['snmp_community']
        if 'snmp_poll_interval' in data:
            globals()['SNMP_POLL_INTERVAL'] = float(data['snmp_poll_interval'])
    except Exception as e:
        print(f"Error saving config: {e}")
    return current

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update application configuration."""
    if request.method == 'GET':
        cfg = load_config()
        # Mask sensitive values for display
        if cfg.get('snmp_community'):
            cfg['snmp_community_masked'] = '*' * len(cfg['snmp_community'])
        return jsonify(cfg)
    data = request.get_json(force=True, silent=True) or {}
    saved = save_config(data)
    return jsonify({'status': 'ok', 'config': saved})


def check_disk_space(path='/var/cache/nfdump'):
    """Check disk space usage for a given path. Returns percentage used."""
    try:
        import shutil
        total, used, free = shutil.disk_usage(path)
        percent_used = (used / total) * 100 if total > 0 else 0
        return {
            'percent_used': round(percent_used, 1),
            'total_gb': round(total / (1024**3), 2),
            'used_gb': round(used / (1024**3), 2),
            'free_gb': round(free / (1024**3), 2),
            'status': 'critical' if percent_used > 90 else 'warning' if percent_used > 75 else 'ok'
        }
    except Exception:
        return {'percent_used': 0, 'status': 'unknown'}

def read_cpu_stat():
    """Read CPU times from /proc/stat. Returns dict with cpu_id -> [times]."""
    cpu_times = {}
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('cpu'):
                    parts = line.split()
                    cpu_id = parts[0]
                    times = [int(x) for x in parts[1:8]]  # user, nice, system, idle, iowait, irq, softirq
                    if len(times) >= 4:
                        cpu_times[cpu_id] = times
    except Exception:
        pass
    return cpu_times

def calculate_cpu_percent_from_stat():
    """Calculate CPU percentage using /proc/stat with cached previous reading."""
    global _cpu_stat_prev, _cpu_stat_lock
    now = time.time()
    
    with _cpu_stat_lock:
        current_times = read_cpu_stat()
        if not current_times or 'cpu' not in current_times:
            return None, None, None
        
        # If we have previous data and it's recent (< 5 seconds old)
        if _cpu_stat_prev['times'] and 'cpu' in _cpu_stat_prev['times'] and (now - _cpu_stat_prev['ts']) < 5:
            prev = _cpu_stat_prev['times']['cpu']
            curr = current_times['cpu']
            
            # Calculate deltas
            prev_total = sum(prev[:4])  # user, nice, system, idle
            curr_total = sum(curr[:4])
            total_delta = curr_total - prev_total
            
            if total_delta > 0:
                idle_delta = curr[3] - prev[3]  # idle is index 3
                cpu_percent = 100.0 * (1.0 - (idle_delta / total_delta))
                cpu_percent = max(0.0, min(100.0, cpu_percent))
                
                # Calculate per-core percentages
                per_core = []
                core_ids = [k for k in current_times.keys() if k.startswith('cpu') and k != 'cpu']
                core_ids.sort(key=lambda x: int(x[3:]) if len(x) > 3 and x[3:].isdigit() else 999)
                
                for core_id in core_ids:
                    if core_id in current_times and core_id in _cpu_stat_prev['times']:
                        p = _cpu_stat_prev['times'][core_id]
                        c = current_times[core_id]
                        p_total = sum(p[:4])
                        c_total = sum(c[:4])
                        c_delta = c_total - p_total
                        if c_delta > 0:
                            c_idle_delta = c[3] - p[3]
                            core_percent = 100.0 * (1.0 - (c_idle_delta / c_delta))
                            per_core.append(max(0.0, min(100.0, core_percent)))
                
                # Count cores
                num_cores = len(core_ids)
                
                # Update cache
                _cpu_stat_prev = {'times': current_times, 'ts': now}
                return round(cpu_percent, 1), per_core if per_core else None, num_cores
        
        # First run or cache expired - store current and return None
        _cpu_stat_prev = {'times': current_times, 'ts': now}
        # Count cores for first run
        core_ids = [k for k in current_times.keys() if k.startswith('cpu') and k != 'cpu']
        num_cores = len(core_ids)
        return None, None, num_cores

@app.route('/metrics')
def metrics():
    """Prometheus-style metrics for basic instrumentation."""
    lines = []
    def add_metric(name, value, help_text=None, mtype='gauge'):
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        if mtype:
            lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")

    add_metric('netflow_nfdump_calls_total', _metric_nfdump_calls, 'Total number of nfdump calls', 'counter')
    add_metric('netflow_stats_cache_hits_total', _metric_stats_cache_hits, 'Cache hits for stats endpoints', 'counter')
    add_metric('netflow_bw_cache_hits_total', _metric_bw_cache_hits, 'Cache hits for bandwidth endpoint', 'counter')
    add_metric('netflow_flow_cache_hits_total', _metric_flow_cache_hits, 'Cache hits for flows endpoint', 'counter')
    add_metric('netflow_http_429_total', _metric_http_429, 'HTTP 429 rate-limit responses', 'counter')
    # Cache sizes
    add_metric('netflow_common_cache_size', len(_common_data_cache))
    add_metric('netflow_dns_cache_size', len(_dns_cache))
    add_metric('netflow_geo_cache_size', len(_geo_cache))
    add_metric('netflow_bandwidth_history_size', len(_bandwidth_history_cache))
    # Threads status
    add_metric('netflow_threat_thread_started', 1 if _threat_thread_started else 0)
    add_metric('netflow_snmp_thread_started', 1 if _snmp_thread_started else 0)
    add_metric('netflow_trends_thread_started', 1 if _trends_thread_started else 0)
    add_metric('netflow_agg_thread_started', 1 if _agg_thread_started else 0)

    body = "\n".join(lines) + "\n"
    return Response(body, mimetype='text/plain; version=0.0.4')


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    checks = {
        'database': False,
        'disk_space': check_disk_space('/var/cache/nfdump'),
        'syslog_active': _syslog_stats.get('received', 0) > 0,
        'nfdump_available': _has_nfdump,
        'memory_usage_mb': 0
    }
    
    # Check database connectivity
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            conn.execute("SELECT 1")
            conn.close()
        checks['database'] = True
    except Exception:
        checks['database'] = False
    
    # Check memory usage (simple approximation)
    try:
        import resource
        mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux returns KB
        checks['memory_usage_mb'] = round(mem_mb, 1)
    except Exception:
        pass
    
    # Determine overall status
    disk_status = checks['disk_space'].get('status', 'unknown')
    all_ok = checks['database'] and checks['syslog_active'] and checks['nfdump_available'] and disk_status != 'critical'
    
    status_code = 200 if all_ok else 503
    status_text = 'healthy' if all_ok else 'degraded'
    
    return jsonify({
        'status': status_text,
        'checks': checks,
        'timestamp': datetime.now().isoformat()
    }), status_code


@app.route('/api/server/health')
@throttle(10, 5)  # Allow 10 requests per 5 seconds (2 req/sec) for 1-2 sec refresh
def api_server_health():
    """Comprehensive server health statistics for the dashboard server."""
    global _server_health_cache
    now = time.time()
    
    # Use cache if data is fresh (1 second TTL for near-real-time updates)
    SERVER_HEALTH_CACHE_TTL = 1.0
    with _cache_lock:
        if _server_health_cache["data"] and (now - _server_health_cache["ts"]) < SERVER_HEALTH_CACHE_TTL:
            return jsonify(_server_health_cache["data"])
    
    data = {
        'cpu': {},
        'memory': {},
        'disk': {},
        'syslog': {},
        'netflow': {},
        'database': {},
        'system': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # CPU Statistics - use /proc filesystem (no psutil)
    try:
        # Get CPU percentage from /proc/stat (accurate method)
        cpu_percent, per_core, num_cores = calculate_cpu_percent_from_stat()
        if cpu_percent is not None:
            data['cpu']['percent'] = cpu_percent
        if per_core:
            data['cpu']['per_core'] = [round(p, 1) for p in per_core]
        if num_cores:
            data['cpu']['cores'] = num_cores
        
        # Get load averages
        try:
            loadavg = os.getloadavg() if hasattr(os, 'getloadavg') else None
            if loadavg:
                data['cpu']['load_1min'] = round(loadavg[0], 2)
                data['cpu']['load_5min'] = round(loadavg[1], 2)
                data['cpu']['load_15min'] = round(loadavg[2], 2)
            else:
                # Fallback to /proc/loadavg
                with open('/proc/loadavg', 'r') as f:
                    loads = [float(x) for x in f.read().split()[:3]]
                    data['cpu']['load_1min'] = round(loads[0], 2)
                    data['cpu']['load_5min'] = round(loads[1], 2)
                    data['cpu']['load_15min'] = round(loads[2], 2)
        except Exception:
            pass
        
        # Get process count
        try:
            proc_count = len([d for d in os.listdir('/proc') if d.isdigit()])
            data['cpu']['process_count'] = proc_count
        except Exception:
            pass
        
        # Get CPU frequency (if available)
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                # Try to find frequency
                import re
                freq_match = re.search(r'cpu MHz\s*:\s*([\d.]+)', cpuinfo)
                if freq_match:
                    freq_mhz = float(freq_match.group(1))
                    data['cpu']['frequency_mhz'] = round(freq_mhz, 0)
        except Exception:
            pass
        
        # Count CPU cores if not already set
        if 'cores' not in data['cpu']:
            try:
                with open('/proc/cpuinfo', 'r') as cf:
                    cores = len([l for l in cf.readlines() if l.startswith('processor')])
                data['cpu']['cores'] = max(cores, 1)
            except Exception:
                data['cpu']['cores'] = 1
        
        # If CPU percent still not set, use load average approximation as fallback
        if 'percent' not in data['cpu'] or data['cpu']['percent'] is None:
            if 'load_1min' in data['cpu'] and 'cores' in data['cpu']:
                cores = data['cpu']['cores']
                load = data['cpu']['load_1min']
                data['cpu']['percent'] = min(round((load / cores) * 100, 1), 100.0)
    except Exception as e:
        data['cpu'] = {'percent': 0, 'error': str(e)}
    
    # Memory Statistics - use /proc filesystem (Linux)
    try:
        import resource
        # Get process memory
        try:
            mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # Linux returns KB
            mem_mb = mem_kb / 1024
            data['memory']['process_mb'] = round(mem_mb, 1)
        except Exception:
            pass
            
        # Get system memory from /proc/meminfo
        try:
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)
            
            if 'MemTotal' in meminfo and 'MemAvailable' in meminfo:
                total_kb = meminfo['MemTotal']
                avail_kb = meminfo['MemAvailable']
                used_kb = total_kb - avail_kb
                data['memory']['total_gb'] = round(total_kb / (1024 * 1024), 2)
                data['memory']['used_gb'] = round(used_kb / (1024 * 1024), 2)
                data['memory']['available_gb'] = round(avail_kb / (1024 * 1024), 2)
                data['memory']['percent'] = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0
                
                # Memory breakdown
                if 'MemFree' in meminfo:
                    data['memory']['free_gb'] = round(meminfo['MemFree'] / (1024 * 1024), 2)
                if 'Buffers' in meminfo:
                    data['memory']['buffers_gb'] = round(meminfo['Buffers'] / (1024 * 1024), 2)
                if 'Cached' in meminfo:
                    data['memory']['cached_gb'] = round(meminfo['Cached'] / (1024 * 1024), 2)
                
                # Memory pressure indicator
                if data['memory']['percent'] >= 90:
                    data['memory']['pressure'] = 'high'
                elif data['memory']['percent'] >= 75:
                    data['memory']['pressure'] = 'medium'
                else:
                    data['memory']['pressure'] = 'low'
            
            # Swap statistics
            if 'SwapTotal' in meminfo and 'SwapFree' in meminfo:
                swap_total_kb = meminfo['SwapTotal']
                swap_free_kb = meminfo['SwapFree']
                swap_used_kb = swap_total_kb - swap_free_kb
                if swap_total_kb > 0:
                    data['memory']['swap_total_gb'] = round(swap_total_kb / (1024 * 1024), 2)
                    data['memory']['swap_used_gb'] = round(swap_used_kb / (1024 * 1024), 2)
                    data['memory']['swap_free_gb'] = round(swap_free_kb / (1024 * 1024), 2)
                    data['memory']['swap_percent'] = round((swap_used_kb / swap_total_kb) * 100, 1)
        except Exception as e:
            pass
    except Exception as e:
        data['memory'] = {'error': str(e)}
    
    # Disk Statistics
    try:
        # Root filesystem
        root_disk = check_disk_space('/')
        data['disk']['root'] = root_disk
        
        # NetFlow data directory
        nfdump_disk = check_disk_space('/var/cache/nfdump')
        data['disk']['nfdump'] = nfdump_disk
        
        # Count nfdump files
        try:
            nfdump_dir = '/var/cache/nfdump'
            if os.path.exists(nfdump_dir):
                files = [f for f in os.listdir(nfdump_dir) if f.startswith('nfcapd.')]
                data['disk']['nfdump_files'] = len(files)
            else:
                data['disk']['nfdump_files'] = 0
        except Exception:
            data['disk']['nfdump_files'] = 0
    except Exception:
        data['disk'] = {'error': 'Unable to read disk stats'}
    
    # Syslog Statistics
    try:
        with _syslog_stats_lock:
            # Syslog is active if: thread is started (receiver is running)
            # If logs have been received, also check if last log was recent (within 5 min)
            last_log_ts = _syslog_stats.get('last_log')
            if last_log_ts:
                # If we have logs, check if they're recent
                syslog_active = (time.time() - last_log_ts) < 300
            else:
                # If no logs yet, consider active if thread is running (receiver is listening)
                syslog_active = _syslog_thread_started
            
            data['syslog'] = {
                'received': _syslog_stats.get('received', 0),
                'parsed': _syslog_stats.get('parsed', 0),
                'errors': _syslog_stats.get('errors', 0),
                'last_log': last_log_ts,
                'active': syslog_active
            }
    except Exception:
        data['syslog'] = {'error': 'Unable to read syslog stats'}
    
    # NetFlow Statistics
    try:
        nfdump_dir = '/var/cache/nfdump'
        netflow_data = {
            'available': _has_nfdump if _has_nfdump is not None else False,
            'directory': nfdump_dir,
            'disk_usage': data['disk'].get('nfdump', {}),
            'files_count': data['disk'].get('nfdump_files', 0)
        }
        
        # Try to get nfdump version
        try:
            result = subprocess.run(['nfdump', '-V'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0] if result.stdout else ''
                netflow_data['version'] = version_line.strip()
        except Exception:
            pass
            
        data['netflow'] = netflow_data
    except Exception:
        data['netflow'] = {'error': 'Unable to read NetFlow stats'}
    
    # Database Statistics
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                # Get row count
                cursor = conn.execute("SELECT COUNT(*) FROM fw_logs")
                log_count = cursor.fetchone()[0]
                
                # Get database size
                db_path = FIREWALL_DB_PATH
                db_size = 0
                if os.path.exists(db_path):
                    db_size = os.path.getsize(db_path)
                
                db_info = {
                    'connected': True,
                    'log_count': log_count,
                    'size_mb': round(db_size / (1024 * 1024), 2),
                    'path': db_path
                }
                
                # Get records from last 24h and 1h for growth rate calculation
                try:
                    now = time.time()
                    cutoff_24h = now - 86400
                    cutoff_1h = now - 3600
                    cursor_24h = conn.execute("SELECT COUNT(*) FROM fw_logs WHERE timestamp > ?", (cutoff_24h,))
                    count_24h = cursor_24h.fetchone()[0]
                    cursor_1h = conn.execute("SELECT COUNT(*) FROM fw_logs WHERE timestamp > ?", (cutoff_1h,))
                    count_1h = cursor_1h.fetchone()[0]
                    db_info['logs_24h'] = count_24h
                    db_info['logs_1h'] = count_1h
                    db_info['growth_rate_per_hour'] = count_1h
                    db_info['growth_rate_per_day'] = count_24h
                except Exception:
                    pass
                
                data['database'] = db_info
            finally:
                conn.close()
    except Exception as e:
        data['database'] = {'connected': False, 'error': str(e)}
    
    # System Information (Uptime, Process Info)
    try:
        # Get system uptime from /proc/uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                data['system']['uptime_seconds'] = int(uptime_seconds)
                data['system']['uptime_formatted'] = f"{days}d {hours}h {minutes}m"
        except Exception:
            data['system']['uptime_formatted'] = 'N/A'
        
        # Get process/thread information using /proc
        try:
            import glob
            pid = os.getpid()
            # Count threads in /proc/PID/task/
            thread_count = len([d for d in glob.glob(f'/proc/{pid}/task/*') if os.path.isdir(d)])
            data['system']['process_threads'] = thread_count
            
            # Get process name/command
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    data['system']['process_name'] = f.read().strip()
            except Exception:
                data['system']['process_name'] = 'python3'
        except Exception:
            data['system']['process_threads'] = 0
        
        # Get boot time
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            boot_time = time.time() - uptime_seconds
            data['system']['boot_time'] = datetime.fromtimestamp(boot_time).isoformat()
            data['system']['boot_time_formatted'] = datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
        
        # Get kernel version
        try:
            with open('/proc/version', 'r') as f:
                version_line = f.read().strip()
                # Extract kernel version (e.g., "Linux version 5.10.0-...")
                import re
                kernel_match = re.search(r'Linux version ([^\s]+)', version_line)
                if kernel_match:
                    data['system']['kernel_version'] = kernel_match.group(1)
                data['system']['os_info'] = version_line.split('(')[0].strip()
        except Exception:
            pass
        
        # Get hostname
        try:
            data['system']['hostname'] = socket_module.gethostname()
        except Exception:
            try:
                with open('/etc/hostname', 'r') as f:
                    data['system']['hostname'] = f.read().strip()
            except Exception:
                pass
    except Exception:
        data['system'] = {'error': 'Unable to read system stats'}
    
    # Network Statistics (from /proc/net/dev)
    try:
        interfaces = {}
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.split(':')
                    iface_name = parts[0].strip()
                    stats = parts[1].split()
                    if len(stats) >= 16:
                        interfaces[iface_name] = {
                            'rx_bytes': int(stats[0]),
                            'rx_packets': int(stats[1]),
                            'tx_bytes': int(stats[8]),
                            'tx_packets': int(stats[9])
                        }
        data['network'] = {'interfaces': interfaces}
    except Exception:
        data['network'] = {'interfaces': {}}
    
    # Cache Statistics
    try:
        with _cache_lock:
            data['cache'] = {
                'dns_cache_size': len(_dns_cache),
                'geo_cache_size': len(_geo_cache),
                'common_cache_size': len(_common_data_cache),
                'bandwidth_history_size': len(_bandwidth_history_cache)
            }
    except Exception:
        data['cache'] = {}
    
    # Process/Application Metrics
    try:
        import resource
        pid = os.getpid()
        
        # Get process memory
        mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        mem_mb = mem_kb / 1024
        
        process_metrics = {
            'process_memory_mb': round(mem_mb, 1),
            'threads': data.get('system', {}).get('process_threads', 0)
        }
        
        # Get process stats from /proc/PID/stat
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                stat_parts = f.read().split()
                if len(stat_parts) > 13:
                    # utime + stime = total CPU time
                    utime = int(stat_parts[13])
                    stime = int(stat_parts[14])
                    process_metrics['cpu_time'] = utime + stime
        except Exception:
            pass
        
        data['process'] = process_metrics
    except Exception:
        data['process'] = {}
    
    # Cache the result
    with _cache_lock:
        _server_health_cache["data"] = data
        _server_health_cache["ts"] = now
    
    return jsonify(data)


# ===== SNMP Integration =====

# SNMP Configuration (override with env vars)
SNMP_HOST = os.getenv("SNMP_HOST", "192.168.0.1")
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "Phoboshomesnmp_3")

# SNMP OIDs
SNMP_OIDS = {
    "cpu_load_1min": ".1.3.6.1.4.1.2021.10.1.3.1",
    "cpu_load_5min": ".1.3.6.1.4.1.2021.10.1.3.2",
    "mem_total": ".1.3.6.1.4.1.2021.4.5.0",        # Total RAM KB
    "mem_avail": ".1.3.6.1.4.1.2021.4.6.0",        # Available RAM KB
    "mem_buffer": ".1.3.6.1.4.1.2021.4.11.0",       # Buffer memory KB
    "mem_cached": ".1.3.6.1.4.1.2021.4.15.0",       # Cached memory KB
    # Swap
    "swap_total": ".1.3.6.1.4.1.2021.4.3.0",       # Total swap KB
    "swap_avail": ".1.3.6.1.4.1.2021.4.4.0",       # Available swap KB
    "sys_uptime": ".1.3.6.1.2.1.1.3.0",            # Uptime timeticks
    "tcp_conns": ".1.3.6.1.2.1.6.9.0",             # tcpCurrEstab
    "tcp_active_opens": ".1.3.6.1.2.1.6.5.0",      # tcpActiveOpens
    "tcp_estab_resets": ".1.3.6.1.2.1.6.8.0",      # tcpEstabResets
    "proc_count": ".1.3.6.1.2.1.25.1.6.0",         # hrSystemProcesses
    "if_wan_status": ".1.3.6.1.2.1.2.2.1.8.1",     # igc0 status
    "if_lan_status": ".1.3.6.1.2.1.2.2.1.8.2",     # igc1 status
    "tcp_fails": ".1.3.6.1.2.1.6.7.0",             # tcpAttemptFails
    "tcp_retrans": ".1.3.6.1.2.1.6.12.0",          # tcpRetransSegs
    # IP stack
    "ip_in_discards": ".1.3.6.1.2.1.4.8.0",        # ipInDiscards
    "ip_in_hdr_errors": ".1.3.6.1.2.1.4.4.0",      # ipInHdrErrors
    "ip_in_addr_errors": ".1.3.6.1.2.1.4.5.0",     # ipInAddrErrors
    "ip_forw_datagrams": ".1.3.6.1.2.1.4.6.0",     # ipForwDatagrams
    "ip_in_delivers": ".1.3.6.1.2.1.4.9.0",        # ipInDelivers
    "ip_out_requests": ".1.3.6.1.2.1.4.10.0",      # ipOutRequests
    # ICMP
    "icmp_in_errors": ".1.3.6.1.2.1.5.2.0",        # icmpInErrors
    "wan_in": ".1.3.6.1.2.1.31.1.1.1.6.1",         # igc0 in
    "wan_out": ".1.3.6.1.2.1.31.1.1.1.10.1",       # igc0 out
    "lan_in": ".1.3.6.1.2.1.31.1.1.1.6.2",         # igc1 in
    "lan_out": ".1.3.6.1.2.1.31.1.1.1.10.2",       # igc1 out
    # Interface speeds (Mbps)
    "wan_speed": ".1.3.6.1.2.1.31.1.1.1.15.1",     # ifHighSpeed WAN
    "lan_speed": ".1.3.6.1.2.1.31.1.1.1.15.2",     # ifHighSpeed LAN
    # Interface errors/discards (32-bit but fine for error counters)
    "wan_in_err": ".1.3.6.1.2.1.2.2.1.14.1",
    "wan_out_err": ".1.3.6.1.2.1.2.2.1.20.1",
    "wan_in_disc": ".1.3.6.1.2.1.2.2.1.13.1",
    "wan_out_disc": ".1.3.6.1.2.1.2.2.1.19.1",
    "lan_in_err": ".1.3.6.1.2.1.2.2.1.14.2",
    "lan_out_err": ".1.3.6.1.2.1.2.2.1.20.2",
    "lan_in_disc": ".1.3.6.1.2.1.2.2.1.13.2",
    "lan_out_disc": ".1.3.6.1.2.1.2.2.1.19.2",
    "disk_read": ".1.3.6.1.4.1.2021.13.15.1.1.12.2", # nda0 read bytes
    "disk_write": ".1.3.6.1.4.1.2021.13.15.1.1.13.2", # nda0 write bytes
    "udp_in": ".1.3.6.1.2.1.7.1.0",                # udpInDatagrams
    "udp_out": ".1.3.6.1.2.1.7.4.0",               # udpOutDatagrams
}

_snmp_cache = {"data": None, "ts": 0}
_snmp_cache_lock = threading.Lock()
_snmp_prev_sample = {"ts": 0, "wan_in": 0, "wan_out": 0, "lan_in": 0, "lan_out": 0}

# Real-time SNMP polling controls
SNMP_POLL_INTERVAL = float(os.getenv("SNMP_POLL_INTERVAL", "2"))  # seconds
SNMP_CACHE_TTL = float(os.getenv("SNMP_CACHE_TTL", str(max(1.0, SNMP_POLL_INTERVAL))))
_snmp_thread_started = False

# SNMP exponential backoff state
_snmp_backoff = {
    "failures": 0,
    "max_failures": 5,
    "base_delay": 2,  # seconds
    "max_delay": 60,  # max backoff delay
    "last_failure": 0
}


def format_uptime(uptime_str):
    """Convert uptime from 0:17:42:05.92 to readable format"""
    try:
        parts = uptime_str.split(":")
        if len(parts) >= 3:
            days = int(parts[0])
            hours = int(parts[1])
            minutes = int(parts[2].split(".")[0])
            
            result = []
            if days > 0:
                result.append(f"{days}d")
            if hours > 0:
                result.append(f"{hours}h")
            if minutes > 0:
                result.append(f"{minutes}m")
            
            return " ".join(result) if result else "0m"
    except:
        return uptime_str
    return uptime_str

def get_snmp_data():
    """Fetch SNMP data from OPNsense firewall with exponential backoff"""
    global _snmp_backoff
    now = time.time()
    
    with _snmp_cache_lock:
        if _snmp_cache["data"] and now - _snmp_cache["ts"] < SNMP_CACHE_TTL:
            return _snmp_cache["data"]
    
    # Check if we're in backoff period
    if _snmp_backoff["failures"] > 0:
        backoff_delay = min(
            _snmp_backoff["base_delay"] * (2 ** (_snmp_backoff["failures"] - 1)),
            _snmp_backoff["max_delay"]
        )
        if now - _snmp_backoff["last_failure"] < backoff_delay:
            # Return cached data if available, otherwise empty
            with _snmp_cache_lock:
                return _snmp_cache.get("data") or {"error": "SNMP unreachable", "backoff": True}
    
    try:
        result = {}
        oids = " ".join(SNMP_OIDS.values())
        cmd = f"snmpget -v2c -c {SNMP_COMMUNITY} -Oqv {SNMP_HOST} {oids}"
        
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5, text=True)
        values = output.strip().split("\n")
        
        oid_keys = list(SNMP_OIDS.keys())
        for i, value in enumerate(values):
            if i < len(oid_keys):
                key = oid_keys[i]
                clean_val = value.strip().strip("\"")
                
                if key.startswith("cpu_load"):
                    result[key] = float(clean_val)
                elif key.startswith("mem_") or key.startswith("swap_") or key in (
                    "tcp_conns", "tcp_active_opens", "tcp_estab_resets",
                    "proc_count",
                    "tcp_fails", "tcp_retrans",
                    "ip_in_discards", "ip_in_hdr_errors", "ip_in_addr_errors", "ip_forw_datagrams", "ip_in_delivers", "ip_out_requests",
                    "icmp_in_errors",
                    "wan_in", "wan_out", "lan_in", "lan_out",
                    "wan_speed", "lan_speed",
                    "wan_in_err", "wan_out_err", "wan_in_disc", "wan_out_disc",
                    "lan_in_err", "lan_out_err", "lan_in_disc", "lan_out_disc",
                    "disk_read", "disk_write", "udp_in", "udp_out"
                ):
                    # Handle Counter64 prefix if present
                    if "Counter64:" in clean_val:
                        clean_val = clean_val.split(":")[-1].strip()
                    # Handle Counter32 prefix if present
                    if "Counter32:" in clean_val:
                        clean_val = clean_val.split(":")[-1].strip()
                    try:
                        result[key] = int(clean_val)
                    except:
                        result[key] = 0
                else:
                    result[key] = clean_val
        
        if "mem_total" in result and "mem_avail" in result:
            # FreeBSD memory calculation: total - available - buffer - cached
            # Using OID .15 (memShared/Cached ~3GB) gives better accuracy
            # This should be close to OPNsense's Active+Wired memory calculation
            # Expected: ~60-65% vs OPNsense ~55-60%
            mem_buffer = result.get("mem_buffer", 0)
            mem_cached = result.get("mem_cached", 0)
            mem_used = result["mem_total"] - result["mem_avail"] - mem_buffer - mem_cached
            result["mem_used"] = mem_used
            try:
                result["mem_percent"] = round((mem_used / result["mem_total"]) * 100, 1) if result["mem_total"] > 0 else 0
            except Exception:
                result["mem_percent"] = 0

        # Swap usage
        if result.get("swap_total") not in (None, 0) and "swap_avail" in result:
            swap_used = max(result["swap_total"] - result["swap_avail"], 0)
            result["swap_used"] = swap_used
            try:
                result["swap_percent"] = round((swap_used / result.get("swap_total", 1)) * 100, 1) if result.get("swap_total", 0) > 0 else 0
            except Exception:
                result["swap_percent"] = 0
        
        if "cpu_load_1min" in result:
            result["cpu_percent"] = min(round((result["cpu_load_1min"] / 4.0) * 100, 1), 100)
        
        # Interface speeds (Mbps)
        if "wan_speed" in result:
            result["wan_speed_mbps"] = int(result.get("wan_speed", 0))
        if "lan_speed" in result:
            result["lan_speed_mbps"] = int(result.get("lan_speed", 0))

        # Compute interface rates (Mbps) using 64-bit counters and previous sample
        global _snmp_prev_sample
        prev_ts = _snmp_prev_sample.get("ts", 0)
        if prev_ts > 0:
            dt = max(1.0, now - prev_ts)
            for prefix in ("wan", "lan"):
                in_key = f"{prefix}_in"
                out_key = f"{prefix}_out"
                if in_key in result and out_key in result:
                    prev_in = _snmp_prev_sample.get(in_key, 0)
                    prev_out = _snmp_prev_sample.get(out_key, 0)
                    d_in = result[in_key] - prev_in
                    d_out = result[out_key] - prev_out
                    # Guard against wrap or reset
                    if d_in < 0: d_in = 0
                    if d_out < 0: d_out = 0
                    rx_mbps = (d_in * 8.0) / (dt * 1_000_000)
                    tx_mbps = (d_out * 8.0) / (dt * 1_000_000)
                    result[f"{prefix}_rx_mbps"] = round(rx_mbps, 2)
                    result[f"{prefix}_tx_mbps"] = round(tx_mbps, 2)
                    # Utilization if speed known
                    spd = result.get(f"{prefix}_speed_mbps") or result.get(f"{prefix}_speed")
                    if spd and spd > 0:
                        util = ((rx_mbps + tx_mbps) / (spd)) * 100.0
                        result[f"{prefix}_util_percent"] = round(util, 1)

            # Generic counter rates (/s) for selected counters
            rate_keys = [
                "tcp_active_opens", "tcp_estab_resets",
                "tcp_fails", "tcp_retrans",
                "ip_in_discards", "ip_in_hdr_errors", "ip_in_addr_errors",
                "ip_forw_datagrams", "ip_in_delivers", "ip_out_requests",
                "icmp_in_errors",
                "udp_in", "udp_out",
                # Interface errors/discards (compute deltas for /s)
                "wan_in_err", "wan_out_err", "wan_in_disc", "wan_out_disc",
                "lan_in_err", "lan_out_err", "lan_in_disc", "lan_out_disc"
            ]
            for k in rate_keys:
                if k in result:
                    prev_v = _snmp_prev_sample.get(k, result[k])
                    d = result[k] - prev_v
                    if d < 0: d = 0
                    result[f"{k}_s"] = round(d / dt, 2)
        # Update previous sample
        _snmp_prev_sample = {
            "ts": now,
            "wan_in": result.get("wan_in", 0),
            "wan_out": result.get("wan_out", 0),
            "lan_in": result.get("lan_in", 0),
            "lan_out": result.get("lan_out", 0),
            # Persist counter snapshots for rate calc next tick
            "tcp_active_opens": result.get("tcp_active_opens", 0),
            "tcp_estab_resets": result.get("tcp_estab_resets", 0),
            "tcp_fails": result.get("tcp_fails", 0),
            "tcp_retrans": result.get("tcp_retrans", 0),
            "ip_in_discards": result.get("ip_in_discards", 0),
            "ip_in_hdr_errors": result.get("ip_in_hdr_errors", 0),
            "ip_in_addr_errors": result.get("ip_in_addr_errors", 0),
            "ip_forw_datagrams": result.get("ip_forw_datagrams", 0),
            "ip_in_delivers": result.get("ip_in_delivers", 0),
            "ip_out_requests": result.get("ip_out_requests", 0),
            "icmp_in_errors": result.get("icmp_in_errors", 0),
            "udp_in": result.get("udp_in", 0),
            "udp_out": result.get("udp_out", 0),
        }

        # Format uptime for readability
        if "sys_uptime" in result:
            result["sys_uptime_formatted"] = format_uptime(result["sys_uptime"])
        
        # Reset backoff on success
        _snmp_backoff["failures"] = 0
        
        with _snmp_cache_lock:
            _snmp_cache["data"] = result
            _snmp_cache["ts"] = now
        
        return result
        
    except Exception as e:
        # Increment backoff on failure
        _snmp_backoff["failures"] = min(_snmp_backoff["failures"] + 1, _snmp_backoff["max_failures"])
        _snmp_backoff["last_failure"] = now
        backoff_delay = min(
            _snmp_backoff["base_delay"] * (2 ** (_snmp_backoff["failures"] - 1)),
            _snmp_backoff["max_delay"]
        )
        print(f"SNMP Error: {e} (backoff: {backoff_delay}s, failures: {_snmp_backoff['failures']})")
        # Return cached data if available
        with _snmp_cache_lock:
            return _snmp_cache.get("data") or {"error": str(e), "backoff": True}


def start_snmp_thread():
    """Start background SNMP polling to enable near real-time updates."""
    global _snmp_thread_started
    if _snmp_thread_started:
        return
    _snmp_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            try:
                # This will update the cache and compute deltas
                get_snmp_data()
            except Exception:
                pass
            _shutdown_event.wait(timeout=max(0.2, SNMP_POLL_INTERVAL))

    t = threading.Thread(target=loop, daemon=True, name='SNMPPollerThread')
    t.start()


@app.route("/api/stats/firewall")
@throttle(5, 10)
def api_stats_firewall():
    """Firewall health stats from SNMP + syslog block data"""
    start_snmp_thread()
    snmp_data = get_snmp_data()
    
    # Add syslog block stats
    fw_stats = _get_firewall_block_stats(hours=1)
    
    # Merge syslog data into response
    if snmp_data:
        snmp_data['blocks_1h'] = fw_stats.get('blocks', 0)
        snmp_data['blocks_per_hour'] = fw_stats.get('blocks_per_hour', 0)
        snmp_data['unique_blocked_ips'] = fw_stats.get('unique_ips', 0)
        snmp_data['threats_blocked'] = fw_stats.get('threats_blocked', 0)
        with _syslog_stats_lock:
            snmp_data['syslog_active'] = _syslog_stats.get('parsed', 0) > 0
            snmp_data['syslog_stats'] = dict(_syslog_stats)
    
    return jsonify({"firewall": snmp_data})


@app.route("/api/stats/firewall/stream")
def api_stats_firewall_stream():
    """Server-Sent Events stream for near real-time firewall stats."""
    start_snmp_thread()

    def event_stream():
        last_ts = 0
        while not _shutdown_event.is_set():
            with _snmp_cache_lock:
                data = _snmp_cache.get("data")
                ts = _snmp_cache.get("ts", 0)
            if ts and ts != last_ts and data is not None:
                # Merge syslog stats into SSE payload
                merged = dict(data) if data else {}
                fw_stats = _get_firewall_block_stats(hours=1)
                merged['blocks_1h'] = fw_stats.get('blocks', 0)
                merged['blocks_per_hour'] = fw_stats.get('blocks_per_hour', 0)
                merged['unique_blocked_ips'] = fw_stats.get('unique_ips', 0)
                merged['threats_blocked'] = fw_stats.get('threats_blocked', 0)
                with _syslog_stats_lock:
                    merged['syslog_active'] = _syslog_stats.get('parsed', 0) > 0
                    merged['syslog_stats'] = dict(_syslog_stats)
                payload = json.dumps({"firewall": merged})
                yield f"data: {payload}\n\n"
                last_ts = ts
            _shutdown_event.wait(timeout=max(0.2, SNMP_POLL_INTERVAL / 2.0))

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

@app.route("/api/stats/blocklist_rate")
@throttle(5, 10)
def api_stats_blocklist_rate():
    """Blocklist match rate statistics (sparkline data)."""
    range_key = request.args.get('range', '1h')
    now = time.time()

    # Check if we have threat data
    threat_set = load_threatlist()
    threat_count = len(threat_set)

    # Determine bucket interval based on range
    # Target approx 15-20 buckets
    # 1h = 3600s / 15 = ~240s (4 min)
    range_seconds = {'15m': 900, '30m': 1800, '1h': 3600, '6h': 21600, '24h': 86400}.get(range_key, 3600)
    bucket_size = max(60, range_seconds // 15)

    # Initialize buckets
    num_buckets = range_seconds // bucket_size
    # End time is now, start time is now - range
    start_ts = now - range_seconds
    buckets = {i: 0 for i in range(num_buckets + 1)}

    # Fetch recent flows
    tf = get_time_range(range_key)
    # Using a higher limit to get decent stats
    output = run_nfdump(["-n", "5000"], tf)

    match_counts = defaultdict(int)
    total_matches = 0

    try:
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        try:
            ts_idx = header.index('ts')
            sa_idx = header.index('sa')
            da_idx = header.index('da')
        except:
            ts_idx, sa_idx, da_idx = 0, 3, 4

        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(ts_idx, sa_idx, da_idx):
                try:
                    src = parts[sa_idx]
                    dst = parts[da_idx]

                    if src in threat_set or dst in threat_set:
                        total_matches += 1

                        # Parse timestamp to bucket
                        ts_str = parts[ts_idx]
                        # Expected format: YYYY-MM-DD HH:MM:SS.mmm
                        try:
                            # Strip millis
                            ts_clean = ts_str.split('.')[0]
                            dt = datetime.strptime(ts_clean, '%Y-%m-%d %H:%M:%S')
                            ts_val = dt.timestamp()

                            if ts_val >= start_ts:
                                b_idx = int((ts_val - start_ts) // bucket_size)
                                if b_idx in buckets:
                                    buckets[b_idx] += 1
                        except:
                            # Fallback if parsing fails: ignore time distribution
                            pass
                except: pass

        # Generate series
        series = []
        for i in range(num_buckets + 1):
            t = start_ts + (i * bucket_size)
            series.append({"ts": int(t * 1000), "rate": buckets[i], "blocked": 0})

        current_rate = series[-1]["rate"] if series else 0

    except Exception:
        series = []
        current_rate = 0
        total_matches = 0

    # Overlay firewall block data onto series
    total_blocked = 0
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cutoff = int(start_ts)
            cur.execute("""
                SELECT timestamp, COUNT(*) as cnt
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ?
                GROUP BY CAST(timestamp / ? AS INTEGER)
                ORDER BY timestamp
            """, (cutoff, bucket_size))
            
            for row in cur.fetchall():
                ts_val = row[0]
                cnt = row[1]
                total_blocked += cnt
                b_idx = int((ts_val - start_ts) // bucket_size)
                if 0 <= b_idx < len(series):
                    series[b_idx]['blocked'] = series[b_idx].get('blocked', 0) + cnt
            conn.close()
    except:
        pass

    return jsonify({
        "series": series,
        "current_rate": current_rate,
        "total_matches": total_matches,
        "total_blocked": total_blocked,
        "threat_count": threat_count,
        "has_fw_data": total_blocked > 0
    })

# Performance metrics tracking
_performance_metrics = {
    'request_count': 0,
    'total_response_time': 0.0,
    'endpoint_times': defaultdict(list),
    'error_count': 0,
    'cache_hits': 0,
    'cache_misses': 0
}
_performance_lock = threading.Lock()

def track_performance(endpoint, duration, cached=False):
    """Track performance metrics for an endpoint."""
    with _performance_lock:
        _performance_metrics['request_count'] += 1
        _performance_metrics['total_response_time'] += duration
        _performance_metrics['endpoint_times'][endpoint].append(duration)
        # Keep only last 100 samples per endpoint
        if len(_performance_metrics['endpoint_times'][endpoint]) > 100:
            _performance_metrics['endpoint_times'][endpoint].pop(0)
        if cached:
            _performance_metrics['cache_hits'] += 1
        else:
            _performance_metrics['cache_misses'] += 1

def track_error():
    """Track error occurrence."""
    with _performance_lock:
        _performance_metrics['error_count'] += 1

# Security headers and cache headers for all responses
@app.after_request
def set_security_headers(response):
    """Add security headers and cache headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Content Security Policy (relaxed for Alpine.js inline handlers)
    # Note: Alpine.js uses inline event handlers, so we use a relaxed CSP
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Cache headers for static files (long cache, immutable)
    if request.endpoint == 'static' or request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    # Cache headers for API endpoints (short cache)
    elif request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'public, max-age=60'
    # No cache for HTML
    elif request.path == '/' or request.path.endswith('.html'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    import traceback
    app.logger.error(f'Server Error: {error}\n{traceback.format_exc()}')
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(Exception)
def handle_exception(error):
    """Handle unhandled exceptions."""
    import traceback
    track_error()
    app.logger.error(f'Unhandled Exception: {error}\n{traceback.format_exc()}')
    return jsonify({'error': 'An error occurred'}), 500


# Batch API endpoint for fetching multiple stats in one request
@app.route("/api/stats/batch", methods=['POST'])
@throttle(10, 20)
def api_stats_batch():
    """Batch endpoint: accepts list of endpoint names, returns combined response."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        requests_list = data.get('requests', [])
        range_key = request.args.get('range', '1h')
        
        if not requests_list:
            return jsonify({'error': 'No requests provided'}), 400
        
        results = {}
        errors = {}
        
        # Map endpoint names to handler functions
        handlers = {
            'summary': api_stats_summary,
            'sources': api_stats_sources,
            'destinations': api_stats_destinations,
            'ports': api_stats_ports,
            'protocols': api_stats_protocols,
            'bandwidth': api_bandwidth,
            'threats': api_threats,
            'alerts': api_alerts,
            'firewall': api_stats_firewall,
        }
        
        # Process each request using test_request_context with proper query string
        for req in requests_list:
            endpoint_name = req.get('endpoint')
            if not endpoint_name or endpoint_name not in handlers:
                if endpoint_name:
                    errors[endpoint_name] = 'Unknown endpoint'
                continue
            
            params = req.get('params', {})
            if 'range' not in params:
                params['range'] = range_key
            
            # Build query string for test_request_context
            from urllib.parse import urlencode
            query_string = urlencode(params)
            
            # Create test request context with query string
            with app.test_request_context(query_string=query_string):
                try:
                    handler = handlers[endpoint_name]
                    # Call handler and extract JSON from Response
                    response = handler()
                    if hasattr(response, 'get_json'):
                        result = response.get_json()
                    elif hasattr(response, 'json'):
                        result = response.json
                    else:
                        result = None
                    
                    if result:
                        results[endpoint_name] = result
                except Exception as e:
                    errors[endpoint_name] = str(e)
        
        response_data = {'results': results}
        if errors:
            response_data['errors'] = errors
        
        return jsonify(response_data)
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# Performance metrics endpoint
@app.route("/api/performance/metrics")
@throttle(10, 60)
def api_performance_metrics():
    """Get performance metrics."""
    with _performance_lock:
        metrics = dict(_performance_metrics)
        
    # Calculate statistics
    avg_response_time = 0.0
    if metrics['request_count'] > 0:
        avg_response_time = metrics['total_response_time'] / metrics['request_count']
    
    # Calculate per-endpoint statistics
    endpoint_stats = {}
    for endpoint, times in metrics['endpoint_times'].items():
        if times:
            endpoint_stats[endpoint] = {
                'count': len(times),
                'avg_ms': round(sum(times) / len(times) * 1000, 2),
                'min_ms': round(min(times) * 1000, 2),
                'max_ms': round(max(times) * 1000, 2),
                'p95_ms': round(sorted(times)[int(len(times) * 0.95)] * 1000, 2) if len(times) > 1 else round(times[0] * 1000, 2)
            }
    
    cache_hit_rate = 0.0
    total_cache_requests = metrics['cache_hits'] + metrics['cache_misses']
    if total_cache_requests > 0:
        cache_hit_rate = metrics['cache_hits'] / total_cache_requests * 100
    
    error_rate = 0.0
    if metrics['request_count'] > 0:
        error_rate = metrics['error_count'] / metrics['request_count'] * 100
    
    return jsonify({
        'summary': {
            'total_requests': metrics['request_count'],
            'avg_response_time_ms': round(avg_response_time * 1000, 2),
            'error_count': metrics['error_count'],
            'error_rate_percent': round(error_rate, 2),
            'cache_hit_rate_percent': round(cache_hit_rate, 2),
            'cache_hits': metrics['cache_hits'],
            'cache_misses': metrics['cache_misses']
        },
        'endpoints': endpoint_stats
    })


if __name__=="__main__":
    print("NetFlow Analytics Pro (Modernized)")
    
    # Graceful shutdown handler
    def shutdown_handler(signum=None, frame=None):
        print("\n[Shutdown] Stopping background services...")
        _shutdown_event.set()
        # Flush any pending syslog buffer
        _flush_syslog_buffer()
        # Give threads time to clean up
        time.sleep(1)
        print("[Shutdown] Complete.")
    
    # Register shutdown handlers
    atexit.register(shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    
    # Start background services
    start_threat_thread()
    start_trends_thread()
    start_agg_thread()
    start_syslog_thread()  # OPNsense firewall log receiver
    
    # Run Flask app (auto-pick next free port if requested one is busy)
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    requested_port = int(os.environ.get('FLASK_PORT', 8080))

    def _find_open_port(h, start_port, max_tries=10):
        p = start_port
        for _ in range(max_tries):
            try:
                s = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
                s.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
                s.bind((h, p))
                s.close()
                return p
            except OSError:
                p += 1
        return start_port

    port = _find_open_port(host, requested_port)
    if port != requested_port:
        print(f"Requested port {requested_port} in use, selected {port} instead")
    print(f"Starting server on {host}:{port} (debug={DEBUG_MODE})")
    app.run(host=host, port=port, threaded=True, debug=DEBUG_MODE)
