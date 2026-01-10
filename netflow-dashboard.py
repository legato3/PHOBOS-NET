from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import subprocess, time, os, json, smtplib
from email.message import EmailMessage
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

app = Flask(__name__)

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
_lock_conversations = threading.Lock()
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

_mock_data_cache = {"mtime": 0, "rows": [], "output_cache": {}}
# Lock for thread-safe access to mock data cache (performance optimization)
_mock_lock = threading.Lock()

_bandwidth_cache = {"data": None, "ts": 0}
_bandwidth_history_cache = {}
_conversations_cache = {"data": None, "ts": 0}
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

_spark_cache = {"src": {"labels": [], "data": {}, "ts": 0}, "dst": {"labels": [], "data": {}, "ts": 0}}
_spark_cache_ttl = 600  # seconds
_spark_bucket_minutes = 180
_spark_bucket_count = 8
_spark_lock = threading.Lock()

_alert_type_ts = {}
_alert_day_counts = defaultdict(int)
ALERT_TYPE_MIN_INTERVAL = {'threat_ip': 120, 'suspicious_port': 300, 'large_transfer': 300, 'default': 300}
ALERT_DAILY_CAP = 30
ALERT_LOG = '/root/netflow-alerts.log'

_ip_detail_cache = {}
_ip_detail_ttl = 180  # seconds

_common_data_cache = {}
_common_data_lock = threading.Lock()

_dns_resolver_executor = ThreadPoolExecutor(max_workers=5)
DNS_CACHE_MAX = 5000

_threat_status = {'last_attempt':0,'last_ok':0,'size':0,'status':'unknown','error':None}

_metric_nfdump_calls = 0
_metric_stats_cache_hits = 0
_metric_bw_cache_hits = 0
_metric_conv_cache_hits = 0
_metric_spark_hits = 0
_metric_spark_misses = 0
_metric_http_429 = 0

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

mmdb_city = None
mmdb_asn = None
_threat_thread_started = False
_agg_thread_started = False

PORTS = {20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",3389:"RDP",5900:"VNC",27017:"MongoDB",1194:"OpenVPN",51820:"WireGuard"}
PROTOS = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",51:"AH"}
SUSPICIOUS_PORTS = [4444,5555,6667,8888,9001,9050,9150,31337,12345,1337,666,6666]
INTERNAL_NETS = ["192.168.","10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31."]

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
_connection_tracker = {}  # {ip: {count: int, bytes: int}}
_seen_external = {"countries": set(), "asns": set()}  # First-seen tracking
_protocol_baseline = {}  # {proto: {"avg_bytes": int, "count": int}}

# Allow override via environment variable, default per project docs
DNS_SERVER = os.getenv("DNS_SERVER", "192.168.0.6")

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
    return any(ip.startswith(net) for net in INTERNAL_NETS)

def get_region(ip):
    if is_internal(ip): return "🏠 Local"
    first = int(ip.split('.')[0])
    if first < 64: return "🌍 Americas"
    elif first < 128: return "🌍 Europe"
    elif first < 192: return "🌏 Asia"
    else: return "🌐 Global"

def flag_from_iso(iso):
    if not iso or len(iso)!=2: return ""
    return chr(ord(iso[0].upper())+127397)+chr(ord(iso[1].upper())+127397)

def load_city_db():
    global mmdb_city
    if mmdb_city is None and os.path.exists(MMDB_CITY):
        try:
            mmdb_city = maxminddb.open_database(MMDB_CITY)
        except Exception:
            mmdb_city = None
    return mmdb_city

def load_asn_db():
    global mmdb_asn
    if mmdb_asn is None and os.path.exists(MMDB_ASN):
        try:
            mmdb_asn = maxminddb.open_database(MMDB_ASN)
        except Exception:
            mmdb_asn = None
    return mmdb_asn

def lookup_geo(ip):
    now = time.time()
    if ip in _geo_cache and now - _geo_cache[ip]['ts'] < _geo_cache_ttl:
        return _geo_cache[ip]['data']
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
                res.update({"country": name, "country_iso": iso, "city": city, "flag": flag_from_iso(iso)})
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

    _geo_cache[ip] = {'ts': now, 'data': res if res else None}
    # LRU-style prune by timestamp if too big
    if len(_geo_cache) > GEO_CACHE_MAX:
        # Drop oldest 5% to reduce churn
        drop = max(1, GEO_CACHE_MAX // 20)
        oldest = sorted(_geo_cache.items(), key=lambda kv: kv[1]['ts'])[:drop]
        for k, _ in oldest:
            _geo_cache.pop(k, None)
    return _geo_cache[ip]['data']

def throttle(max_calls=20, time_window=10):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            endpoint = func.__name__
            with _throttle_lock:
                _request_times[endpoint] = [t for t in _request_times[endpoint] if now - t < time_window]
                if len(_request_times[endpoint]) >= max_calls:
                    global _metric_http_429
                    _metric_http_429 += 1
                    return jsonify({"error": "Rate limit"}), 429
                _request_times[endpoint].append(now)
            return func(*args, **kwargs)
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
         out = "ts,te,td,sa,da,sp,dp,proto,flg,fwd,stos,ipkt,ibyt\n"
         for r in rows[:limit]:
             # Reconstruct line
             line = f"{r['ts']},{r['te']},{r['td']},{r['sa']},{r['da']},{r['sp']},{r['dp']},{r['proto']},{r['flg']},0,0,{r['pkts']},{r['bytes']}"
             out += line + "\n"

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

        out = "ts,te,td,sa,da,sp,dp,proto,flg,fwd,stos,ipkt,ibyt\n"
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
            row[5] = str(d['flows']) # flows (matches sp? No, wait. sp is index 5 in header.)
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

            out += ",".join(row) + "\n"

        # We must change the header variable to match
        out = out.replace("ts,te,td,sa,da,sp,dp,proto,flg,fwd,stos,ipkt,ibyt", "ts,te,td,sa,da,sp,dp,proto,flg,flows,stos,ipkt,ibyt")

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
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            if r.returncode == 0 and r.stdout:
                return r.stdout
    except Exception:
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
        feeds_file = '/root/threat-feeds.txt'
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


def calculate_security_score():
    """Calculate 0-100 security score based on current threat state"""
    score = 100
    reasons = []
    
    # Threat detections penalty (up to -40 points)
    threat_count = len([ip for ip in _threat_timeline if time.time() - _threat_timeline[ip]['last_seen'] < 3600])
    if threat_count > 0:
        penalty = min(40, threat_count * 10)
        score -= penalty
        reasons.append(f"-{penalty}: {threat_count} active threats")
    
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
        'blocklist_ips': total_ips
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
        while True:
            fetch_threat_feed()
            time.sleep(900)
    t = threading.Thread(target=loop, daemon=True)
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
        if not any(src_ip.startswith(net) for net in INTERNAL_NETS):
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
        if ip and any(ip.startswith(net) for net in INTERNAL_NETS):
            internal_traffic[ip]['out'] += item.get('bytes', 0)
    
    for item in (destinations_data or []):
        ip = item.get('key')
        if ip and any(ip.startswith(net) for net in INTERNAL_NETS):
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
        if not ip or any(ip.startswith(net) for net in INTERNAL_NETS):
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
        
        src_internal = any(src_ip.startswith(net) for net in INTERNAL_NETS)
        dst_internal = any(dst_ip.startswith(net) for net in INTERNAL_NETS)
        
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
        if ip and any(ip.startswith(net) for net in INTERNAL_NETS):
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


def fmt_bytes(b):
    if b >= 1024**3: return f"{b/1024**3:.2f} GB"
    elif b >= 1024**2: return f"{b/1024**2:.2f} MB"
    elif b >= 1024: return f"{b/1024:.2f} KB"
    return f"{b} B"


def load_smtp_cfg():
    if not os.path.exists(SMTP_CFG_PATH): return None
    try:
        with open(SMTP_CFG_PATH,'r') as f: return json.load(f)
    except: return None

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

def send_email(alerts):
    notify = load_notify_cfg()
    if not notify.get("email", True): return
    cfg = load_smtp_cfg()
    if not cfg or not alerts: return
    # ... basic smtp logic ...
    pass

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
    send_email(filtered)
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

    tf = get_time_range(range_key)
    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf), expected_key='sa')
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
        i["region"] = get_region(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
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
        i["region"] = get_region(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
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

    tf = get_time_range(range_key)
    # LIMITED TO 10
    protos_raw = parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","10"], tf), expected_key='proto')

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

    tf = get_time_range(range_key)
    # Re-use top sources logic but aggregate in python
    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","50"], tf), expected_key='sa')

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
        for f in sorted_flows:
            f['bytes_fmt'] = fmt_bytes(f['bytes'])
            f['duration_fmt'] = f"{f['duration']:.2f}s"

        data = {"durations": sorted_flows}
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
    output = run_nfdump(["-n", "2000"], tf)

    # Buckets
    dist = {
        "Tiny (<64B)": 0,
        "Small (64-511B)": 0,
        "Medium (512-1023B)": 0,
        "Large (1024-1513B)": 0,
        "Jumbo (>1513B)": 0
    }

    try:
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        try:
            ibyt_idx = header.index('ibyt')
            ipkt_idx = header.index('ipkt')
        except:
             # Fallback
            ibyt_idx, ipkt_idx = 12, 11

        for line in lines[1:]:
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

    country_bytes = Counter()
    for item in sources + dests:
        ip = item.get("key")
        b = item.get("bytes", 0)
        geo = lookup_geo(ip) or {}
        iso = geo.get('country_iso') or '??'
        name = geo.get('country') or 'Unknown'
        key = f"{name} ({iso})" if iso != '??' else 'Unknown'
        country_bytes[key] += b

    top = country_bytes.most_common(10)
    data = {
        "labels": [k for k,_ in top],
        "bytes": [v for _,v in top],
        "bytes_fmt": [fmt_bytes(v) for _,v in top]
    }
    with _lock_countries:
        _stats_countries_cache["data"] = data
        _stats_countries_cache["ts"] = now
        _stats_countries_cache["key"] = range_key
        _stats_countries_cache["win"] = win
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
    output = run_nfdump(["-O", "bytes", "-n", "100"], tf)

    pairs = {}
    try:
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        try:
            sa_idx = header.index('sa')
            da_idx = header.index('da')
            ibyt_idx = header.index('ibyt')
        except:
            sa_idx, da_idx, ibyt_idx = 3, 4, 12

        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, ibyt_idx):
                try:
                    src = parts[sa_idx]
                    dst = parts[da_idx]
                    b = int(parts[ibyt_idx])
                    pair_key = f"{src}→{dst}"
                    if pair_key in pairs:
                        pairs[pair_key]["bytes"] += b
                    else:
                        pairs[pair_key] = {"src": src, "dst": dst, "bytes": b}
                except: pass

        # Sort by bytes and get top 10
        sorted_pairs = sorted(pairs.values(), key=lambda x: x["bytes"], reverse=True)[:10]
        talkers = []
        for p in sorted_pairs:
            talkers.append({
                "src": p["src"],
                "dst": p["dst"],
                "src_hostname": resolve_ip(p["src"]),
                "dst_hostname": resolve_ip(p["dst"]),
                "bytes": p["bytes"],
                "bytes_fmt": fmt_bytes(p["bytes"]),
                "src_region": get_region(p["src"]),
                "dst_region": get_region(p["dst"])
            })
        data = {"talkers": talkers}
    except:
        data = {"talkers": []}

    with _cache_lock:
        _stats_talkers_cache["data"] = data
        _stats_talkers_cache["ts"] = now
        _stats_talkers_cache["key"] = range_key
        _stats_talkers_cache["win"] = win
    return jsonify(data)


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

    try:
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        try:
            ts_idx = header.index('ts')
            ibyt_idx = header.index('ibyt')
        except:
            ts_idx, ibyt_idx = 0, 12

        for line in lines[1:]:
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
        while True:
            try:
                # Work on the last completed bucket (avoid partial current)
                now_dt = datetime.now()
                current_end = _get_bucket_end(now_dt)
                last_completed_end = current_end - timedelta(minutes=5)
                _ensure_rollup_for_bucket(last_completed_end)
            except Exception:
                pass
            time.sleep(30)

    t = threading.Thread(target=loop, daemon=True)
    t.start()


def start_agg_thread():
    """Background aggregator to precompute common nfdump data for 1h range every 60s."""
    global _agg_thread_started
    if _agg_thread_started:
        return
    _agg_thread_started = True

    def loop():
        while True:
            try:
                range_key = '1h'
                tf = get_time_range(range_key)
                now_ts = time.time()
                win = int(now_ts // 60)

                sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","100"], tf), expected_key='sa')
                sources.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","100"], tf), expected_key='dp')
                ports.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                dests = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","100"], tf), expected_key='da')
                dests.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                protos = parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","20"], tf), expected_key='proto')

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
                # If missing and it's not in the future, attempt on-demand fill once
                if et < now:
                    _ensure_rollup_for_bucket(et)
                    with _trends_db_lock:
                        conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
                        try:
                            cur = conn.execute("SELECT bytes, flows FROM traffic_rollups WHERE bucket_end=?", (et_ts,))
                            row = cur.fetchone()
                        finally:
                            conn.close()
                    if row:
                        total_b, total_f = row[0], row[1]
                        val_bw = round((total_b*8)/(300*1_000_000),2)
                        val_flows = round(total_f/300,2)
                    else:
                        val_bw = 0
                        val_flows = 0
                else:
                    # future/incomplete bucket
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

@app.route("/api/conversations")
@throttle(10,30)
def api_conversations():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_conversations:
        if _conversations_cache.get("data") and _conversations_cache.get("key") == cache_key_local and _conversations_cache.get("win") == win:
            global _metric_conv_cache_hits
            _metric_conv_cache_hits += 1
            return jsonify(_conversations_cache["data"])
    tf = get_time_range(range_key)

    # Fetch raw flows to get actual conversation partners
    # Use -O bytes to sort by bytes descending at nfdump level to get 'Top' conversations
    # If limit > 100, we might need more data.
    fetch_limit = str(max(100, limit))
    output = run_nfdump(["-O", "bytes", "-n", fetch_limit], tf)

    convs = []
    try:
        rows = []
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        try:
            ts_idx = header.index('ts')
            sa_idx = header.index('sa')
            da_idx = header.index('da')
            dp_idx = header.index('dp')
            pr_idx = header.index('proto')
            ibyt_idx = header.index('ibyt')
            ipkt_idx = header.index('ipkt')
        except:
             # Fallback indices (based on mock/nfdump std)
            sa_idx, da_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx = 3, 4, 6, 7, 12, 11

        seen_flows = set()
        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, ibyt_idx):
                try:
                    src = parts[sa_idx]
                    dst = parts[da_idx]
                    # Simple dedup based on src/dst/bytes (not perfect but avoids exact dups)
                    flow_key = (src, dst, parts[pr_idx], parts[dp_idx])
                    if flow_key in seen_flows: continue
                    seen_flows.add(flow_key)

                    rows.append({
                        "src": src, "dst": dst,
                        "dst_port": parts[dp_idx],
                        "proto": parts[pr_idx],
                        "bytes": int(parts[ibyt_idx]),
                        "packets": int(parts[ipkt_idx]) if len(parts) > ipkt_idx else 0
                    })
                except: pass

        # Sort by bytes descending
        rows.sort(key=lambda x: x['bytes'], reverse=True)
        top_rows = rows[:limit]

        for r in top_rows:
            # Map Proto
            proto_val = r['proto']
            if proto_val.isdigit():
                 r['proto_name'] = PROTOS.get(int(proto_val), proto_val)
            else:
                 r['proto_name'] = proto_val

            # Map Service
            try:
                port = int(r['dst_port'])
                r['service'] = PORTS.get(port, str(port))
            except:
                r['service'] = r['dst_port']

            convs.append({
                "src": r['src'], "dst": r['dst'],
                "src_hostname": resolve_ip(r['src']),
                "dst_hostname": resolve_ip(r['dst']),
                "bytes": r['bytes'], "bytes_fmt": fmt_bytes(r['bytes']),
                "src_region": get_region(r['src']),
                "dst_region": get_region(r['dst']),
                "proto": r['proto_name'],
                "port": r['dst_port'],
                "service": r['service'],
                "packets": r['packets']
            })
    except:
        pass  # Parsing error
    data = {"conversations":convs, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    with _lock_conversations:
        _conversations_cache["data"] = data
        _conversations_cache["ts"] = now
        _conversations_cache["key"] = cache_key_local
        _conversations_cache["win"] = win
    return jsonify(data)

@app.route("/api/ip_detail/<ip>")
@throttle(5,10)
def api_ip_detail(ip):
    start_threat_thread()
    dt = datetime.now()
    tf = f"{(dt-timedelta(hours=1)).strftime('%Y/%m/%d.%H:%M:%S')}-{dt.strftime('%Y/%m/%d.%H:%M:%S')}"
    direction = get_traffic_direction(ip, tf)
    src_ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","10","-a",f"src ip {ip}"], tf), expected_key='dp')
    dst_ports = parse_csv(run_nfdump(["-s","srcport/bytes/flows","-n","10","-a",f"dst ip {ip}"], tf), expected_key='sp')
    protocols = parse_csv(run_nfdump(["-s","proto/bytes/packets","-n","5","-a",f"ip {ip}"], tf), expected_key='proto')

    # Enrich
    for p in protocols:
        try:
            proto = int(p["key"]); p["proto_name"] = PROTOS.get(proto, f"Proto-{p['key']}")
        except Exception:
            p["proto_name"] = p["key"]

    geo = lookup_geo(ip)
    data = {
        "ip": ip,
        "hostname": resolve_ip(ip),
        "region": get_region(ip),
        "internal": is_internal(ip),
        "geo": geo,
        "direction": direction,
        "src_ports": src_ports,
        "dst_ports": dst_ports,
        "protocols": protocols,
        "threat": False
    }
    return jsonify(data)


@app.route("/api/trends/source/<ip>")
def api_trends_source(ip):
    """Return 5-min rollup trend for a source IP over the requested range (default 24h)."""
    range_key = request.args.get('range', '24h')
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
        finally:
            conn.close()
    labels = [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in rows]
    bytes_arr = [r[1] for r in rows]
    flows_arr = [r[2] for r in rows]
    return jsonify({"labels": labels, "bytes": bytes_arr, "flows": flows_arr})


@app.route("/api/trends/dest/<ip>")
def api_trends_dest(ip):
    """Return 5-min rollup trend for a destination IP over the requested range (default 24h)."""
    range_key = request.args.get('range', '24h')
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
        finally:
            conn.close()
    labels = [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in rows]
    bytes_arr = [r[1] for r in rows]
    flows_arr = [r[2] for r in rows]
    return jsonify({"labels": labels, "bytes": bytes_arr, "flows": flows_arr})

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


@app.route('/api/stats/threats')
@throttle(5, 10)
def api_threats():
    """Get threat detections with category and geo info"""
    range_key = request.args.get('range', '1h')
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    threat_set = threat_set - whitelist
    
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
            hits.append({
                "ip": ip,
                "category": info.get("category", "UNKNOWN"),
                "feed": info.get("feed", "unknown"),
                "bytes": item.get("bytes", 0),
                "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                "flows": item.get("flows", 0),
                "country": geo.get("country_code", "--"),
                "city": geo.get("city", ""),
                "hits": item.get("flows", 1)
            })
    
    # Sort by bytes descending
    hits.sort(key=lambda x: x["bytes"], reverse=True)
    
    return jsonify({
        "hits": hits[:20],
        "total_threats": len(hits),
        "feed_ips": _threat_status.get("size", 0),
        "threat_status": _threat_status
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
    """Get attack timeline data for visualization (24h hourly breakdown)."""
    now = time.time()
    cutoff = now - 86400  # 24 hours
    
    with _alert_history_lock:
        recent = [a for a in _alert_history if a.get('ts', 0) > cutoff]
    
    # Build hourly buckets
    timeline = []
    for i in range(24):
        hour_start = now - ((23 - i) * 3600)
        hour_end = hour_start + 3600
        hour_label = time.strftime('%H:00', time.localtime(hour_start))
        
        hour_alerts = [a for a in recent if hour_start <= a.get('ts', 0) < hour_end]
        
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for a in hour_alerts:
            by_type[a.get('type', 'unknown')] += 1
            by_severity[a.get('severity', 'low')] += 1
        
        timeline.append({
            'hour': hour_label,
            'timestamp': hour_start,
            'total': len(hour_alerts),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'critical': by_severity.get('critical', 0),
            'high': by_severity.get('high', 0),
            'medium': by_severity.get('medium', 0),
            'low': by_severity.get('low', 0)
        })
    
    # Peak hour
    peak = max(timeline, key=lambda x: x['total']) if timeline else None
    
    return jsonify({
        'timeline': timeline,
        'peak_hour': peak.get('hour') if peak else None,
        'peak_count': peak.get('total') if peak else 0,
        'total_24h': sum(t['total'] for t in timeline)
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
    """Get threat counts grouped by country"""
    country_stats = defaultdict(lambda: {'count': 0, 'ips': [], 'categories': defaultdict(int)})
    
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
    
    # Convert to list and sort
    result = []
    for code, data in country_stats.items():
        result.append({
            'country_code': code,
            'country_name': data.get('name', 'Unknown'),
            'threat_count': data['count'],
            'sample_ips': data['ips'],
            'categories': dict(data['categories'])
        })
    
    result.sort(key=lambda x: x['threat_count'], reverse=True)
    
    return jsonify({
        'countries': result[:20],
        'total_countries': len(result)
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
    global _threat_feed_health
    if _threat_feed_health:
        ok_feeds = sum(1 for f in _threat_feed_health.get('feeds', []) if f.get('status') == 'ok')
        total_feeds = len(_threat_feed_health.get('feeds', []))
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
    add_metric('netflow_conv_cache_hits_total', _metric_conv_cache_hits, 'Cache hits for conversations endpoint', 'counter')
    add_metric('netflow_spark_cache_hits_total', _metric_spark_hits, 'Sparkline cache hits', 'counter')
    add_metric('netflow_spark_cache_misses_total', _metric_spark_misses, 'Sparkline cache misses', 'counter')
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


# ===== SNMP Integration =====
import subprocess
import time
import threading

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
    """Fetch SNMP data from OPNsense firewall"""
    now = time.time()
    
    with _snmp_cache_lock:
        if _snmp_cache["data"] and now - _snmp_cache["ts"] < SNMP_CACHE_TTL:
            return _snmp_cache["data"]
    
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
        
        with _snmp_cache_lock:
            _snmp_cache["data"] = result
            _snmp_cache["ts"] = now
        
        return result
        
    except Exception as e:
        print(f"SNMP Error: {e}")
        return {}


def start_snmp_thread():
    """Start background SNMP polling to enable near real-time updates."""
    global _snmp_thread_started
    if _snmp_thread_started:
        return
    _snmp_thread_started = True

    def loop():
        while True:
            try:
                # This will update the cache and compute deltas
                get_snmp_data()
            except Exception:
                pass
            time.sleep(max(0.2, SNMP_POLL_INTERVAL))

    t = threading.Thread(target=loop, daemon=True)
    t.start()


@app.route("/api/stats/firewall")
@throttle(5, 10)
def api_stats_firewall():
    """Firewall health stats from SNMP"""
    start_snmp_thread()
    data = get_snmp_data()
    return jsonify({"firewall": data})


@app.route("/api/stats/firewall/stream")
def api_stats_firewall_stream():
    """Server-Sent Events stream for near real-time firewall stats."""
    start_snmp_thread()

    def event_stream():
        last_ts = 0
        while True:
            with _snmp_cache_lock:
                data = _snmp_cache.get("data")
                ts = _snmp_cache.get("ts", 0)
            if ts and ts != last_ts and data is not None:
                payload = json.dumps({"firewall": data})
                yield f"data: {payload}\n\n"
                last_ts = ts
            time.sleep(max(0.2, SNMP_POLL_INTERVAL / 2.0))

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

if __name__=="__main__":
    print("NetFlow Analytics Pro (Modernized)")
    app.run(host="0.0.0.0",port=8080,threaded=True)
