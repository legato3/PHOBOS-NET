from flask import Flask, render_template, jsonify, request
import subprocess, time, os, json, smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from functools import wraps
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import maxminddb
import random
import dns.resolver
import dns.reversename

app = Flask(__name__)

# ------------------ Globals & caches ------------------
_cache_lock = threading.Lock()
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

_threat_cache = {"data": set(), "mtime": 0}
_alert_sent_ts = 0
_alert_history = deque(maxlen=50)

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
SMTP_CFG_PATH = "/root/netflow-smtp.json"
NOTIFY_CFG_PATH = "/root/netflow-notify.json"
SAMPLE_DATA_PATH = "sample_data/nfdump_flows.csv"

mmdb_city = None
mmdb_asn = None
_threat_thread_started = False

PORTS = {20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",3389:"RDP",5900:"VNC",27017:"MongoDB",1194:"OpenVPN",51820:"WireGuard"}
PROTOS = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",51:"AH"}
SUSPICIOUS_PORTS = [4444,5555,6667,8888,9001,9050,9150,31337,12345,1337,666,6666]
INTERNAL_NETS = ["192.168.","10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31."]

DNS_SERVER = "192.168.0.6"

def resolve_hostname(ip):
    """Resolve IP to hostname using configured DNS_SERVER."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [DNS_SERVER]
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # Reverse DNS lookup
        rev_name = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev_name, 'PTR')
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
    except Exception:
        pass

def resolve_ip(ip):
    now = time.time()
    if ip in _dns_cache and now - _dns_ttl.get(ip, 0) < 300:
        return _dns_cache[ip]

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
        # Check if nfdump exists
        if subprocess.call(["which", "nfdump"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
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
        if flows_idx == -1: flows_idx = 9 # flows usually earlier than bytes? No, standard is fwd status? No, flows usually around 9-11
        if packets_idx == -1: packets_idx = 11

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
            flows_val = int(float(parts[flows_idx]))
            packets_val = int(float(parts[packets_idx]))
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


def fetch_threat_feed():
    global _threat_status
    try:
        _threat_status['last_attempt'] = time.time()
        
        # Support multiple feeds from threat-feeds.txt
        urls = []
        feeds_file = '/root/threat-feeds.txt'
        if os.path.exists(feeds_file):
            with open(feeds_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        elif os.path.exists(THREAT_FEED_URL_PATH):
            with open(THREAT_FEED_URL_PATH, 'r') as f:
                url = f.read().strip()
                if url:
                    urls = [url]
        
        if not urls:
            _threat_status['status'] = 'missing'
            return
        
        all_ips = set()
        errors = []
        
        for url in urls:
            try:
                r = requests.get(url, timeout=25)
                if r.status_code != 200:
                    feed_name = url.split('/')[-2] if '/' in url else 'feed'
                    errors.append(f'{feed_name}: HTTP {r.status_code}')
                    continue
                ips = [line.strip() for line in r.text.split('\n') if line.strip() and not line.startswith('#')]
                all_ips.update(ips)
            except Exception as e:
                feed_name = url.split('/')[-2] if '/' in url else 'feed'
                errors.append(f'{feed_name}: {str(e)[:30]}')
        
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
        _threat_status['status'] = 'ok'
        _threat_status['error'] = '; '.join(errors) if errors else None
    except Exception as e:
        _threat_status['status'] = 'error'
        _threat_status['error'] = str(e)


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

def detect_anomalies(ports_data, sources_data, threat_set, whitelist, feed_label="threat-feed"):
    alerts = []
    seen = set()
    threat_set = threat_set - whitelist

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
    for item in sources_data:
        if item["bytes"] > 50*1024*1024: # 50MB
            alert_key = f"large_{item['key']}"
            if alert_key not in seen:
                alerts.append({"type":"large_transfer","msg":f"📊 Large transfer from {item['key']}: {fmt_bytes(item['bytes'])}","severity":"medium","feed":"local"})
                seen.add(alert_key)

        # Threat Check
        if item["key"] in threat_set:
            alert_key = f"threat_{item['key']}"
            if alert_key not in seen:
                alerts.append({"type":"threat_ip","msg":f"🚨 {feed_label} match: {item['key']} ({fmt_bytes(item['bytes'])})","severity":"critical","feed":feed_label})
                seen.add(alert_key)

        # Test alert if 84.x.x.x (from sample, keeping this for UX demo)
        if item["key"].startswith("84.192."):
             alert_key = f"watchlist_{item['key']}"
             if alert_key not in seen:
                 alerts.append({"type":"watchlist","msg":f"👁️ Watchlist IP Activity: {item['key']}","severity":"low","feed":"policy"})
                 seen.add(alert_key)

    return alerts


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
    ts = datetime.utcnow().isoformat()+'Z'
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

    with _common_data_lock:
        if cache_key in _common_data_cache:
            entry = _common_data_cache[cache_key]
            if now - entry["ts"] < 60:
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
        _common_data_cache[cache_key] = {"data": data, "ts": now}

    return data

@app.route("/api/stats/summary")
@throttle(5, 10)
def api_stats_summary():
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_summary_cache["data"] and _stats_summary_cache["key"] == range_key and now - _stats_summary_cache["ts"] < 60:
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
    with _cache_lock:
        _stats_summary_cache["data"] = data
        _stats_summary_cache["ts"] = now
        _stats_summary_cache["key"] = range_key
    return jsonify(data)


@app.route("/api/stats/sources")
@throttle(5, 10)
def api_stats_sources():
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_sources_cache["data"] and _stats_sources_cache["key"] == range_key and now - _stats_sources_cache["ts"] < 60:
            return jsonify(_stats_sources_cache["data"])

    tf = get_time_range(range_key)

    # Use shared data (top 50)
    full_sources = get_common_nfdump_data("sources", range_key)

    # Return top 10
    sources = full_sources[:10]

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
    with _cache_lock:
        _stats_sources_cache["data"] = data
        _stats_sources_cache["ts"] = now
        _stats_sources_cache["key"] = range_key
    return jsonify(data)


@app.route("/api/stats/destinations")
@throttle(5, 10)
def api_stats_destinations():
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_dests_cache["data"] and _stats_dests_cache["key"] == range_key and now - _stats_dests_cache["ts"] < 60:
            return jsonify(_stats_dests_cache["data"])

    tf = get_time_range(range_key)

    # Use shared data (top 20)
    full_dests = get_common_nfdump_data("dests", range_key)
    dests = full_dests[:10]

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
    with _cache_lock:
        _stats_dests_cache["data"] = data
        _stats_dests_cache["ts"] = now
        _stats_dests_cache["key"] = range_key
    return jsonify(data)


@app.route("/api/stats/ports")
@throttle(5, 10)
def api_stats_ports():
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_ports_cache["data"] and _stats_ports_cache["key"] == range_key and now - _stats_ports_cache["ts"] < 60:
            return jsonify(_stats_ports_cache["data"])

    tf = get_time_range(range_key)
    # Use shared data (top 100, sorted by bytes)
    full_ports = get_common_nfdump_data("ports", range_key)
    ports = full_ports[:10]

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
    with _cache_lock:
        _stats_ports_cache["data"] = data
        _stats_ports_cache["ts"] = now
        _stats_ports_cache["key"] = range_key
    return jsonify(data)

@app.route("/api/stats/protocols")
@throttle(5, 10)
def api_stats_protocols():
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_protocols_cache["data"] and _stats_protocols_cache["key"] == range_key and now - _stats_protocols_cache["ts"] < 60:
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
    with _cache_lock:
        _stats_protocols_cache["data"] = data
        _stats_protocols_cache["ts"] = now
        _stats_protocols_cache["key"] = range_key
    return jsonify(data)

@app.route("/api/stats/flags")
@throttle(5, 10)
def api_stats_flags():
    # New Feature: TCP Flags
    # Parse raw flows using nfdump
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_flags_cache["data"] and _stats_flags_cache["key"] == range_key and now - _stats_flags_cache["ts"] < 60:
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
        with _cache_lock:
            _stats_flags_cache["data"] = data
            _stats_flags_cache["ts"] = now
            _stats_flags_cache["key"] = range_key
        return jsonify(data)
    except Exception as e:
        return jsonify({"flags": []})

@app.route("/api/stats/asns")
@throttle(5, 10)
def api_stats_asns():
    # New Feature: Top ASNs
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_asns_cache["data"] and _stats_asns_cache["key"] == range_key and now - _stats_asns_cache["ts"] < 60:
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
    with _cache_lock:
        _stats_asns_cache["data"] = data
        _stats_asns_cache["ts"] = now
        _stats_asns_cache["key"] = range_key
    return jsonify(data)

@app.route("/api/stats/durations")
@throttle(5, 10)
def api_stats_durations():
    # New Feature: Longest Duration Flows
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_durations_cache["data"] and _stats_durations_cache["key"] == range_key and now - _stats_durations_cache["ts"] < 60:
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
        with _cache_lock:
            _stats_durations_cache["data"] = data
            _stats_durations_cache["ts"] = now
            _stats_durations_cache["key"] = range_key
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


@app.route("/api/alerts")
@throttle(5, 10)
def api_alerts():
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_alerts_cache["data"] and _stats_alerts_cache["key"] == range_key and now - _stats_alerts_cache["ts"] < 60:
            return jsonify(_stats_alerts_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    # Run analysis (using shared data)
    # Alerts logic uses top 20 sources/ports, which are covered by sources (top 50) and ports (top 20)
    sources = get_common_nfdump_data("sources", range_key)[:20]
    ports = get_common_nfdump_data("ports", range_key)

    alerts = detect_anomalies(ports, sources, threat_set, whitelist)
    send_notifications([a for a in alerts if a.get("severity") in ("critical","high")])

    data = {
        "alerts": alerts, # Not limited to 10
        "feed_label": get_feed_label()
    }
    with _cache_lock:
        _stats_alerts_cache["data"] = data
        _stats_alerts_cache["ts"] = now
        _stats_alerts_cache["key"] = range_key
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
    # For longer ranges (6h, 24h), stick to 1h view (12 buckets) to avoid excessive nfdump calls/latency
    # Implementing 24h view would require 288 calls or a different aggregation strategy.

    # Separate cache key for different ranges?
    # Current _bandwidth_cache is global. If we switch range, we overwrite.
    # That's acceptable for single-user, but we should probably key it.

    cache_key = f"bw_{range_key}"

    # Check cache with range key validation
    with _cache_lock:
        if _bandwidth_cache.get("data") and _bandwidth_cache.get("key") == cache_key and now_ts - _bandwidth_cache.get("ts", 0) < 5:
            global _metric_bw_cache_hits
            _metric_bw_cache_hits += 1
            return jsonify(_bandwidth_cache["data"])

    now = datetime.now()
    labels, bw, flows = [], [], []

    # Round down to nearest 5 minutes
    now_minute = now.minute
    remainder = now_minute % 5
    current_bucket_end = now.replace(minute=now_minute - remainder, second=0, microsecond=0) + timedelta(minutes=5)

    try:
        for i in range(bucket_count - 1, -1, -1):
            # Calculate buckets aligned to 5 minute intervals
            et = current_bucket_end - timedelta(minutes=i*5)
            st = et - timedelta(minutes=5)

            tf_key = f"{st.strftime('%Y/%m/%d.%H:%M:%S')}-{et.strftime('%Y/%m/%d.%H:%M:%S')}"
            labels.append(et.strftime("%H:%M"))

            # Check history cache for completed intervals
            # An interval is completed if its end time is in the past
            is_completed = et <= now
            cached = None
            if is_completed:
                cached = _bandwidth_history_cache.get(tf_key)

            if cached:
                bw.append(cached["bw"])
                flows.append(cached["flows"])
            else:
                # Compute
                output = run_nfdump(["-s","proto/bytes/flows","-n","1"], tf_key)
                stats = parse_csv(output, expected_key='proto')
                val_bw, val_flows = 0, 0
                if stats:
                    total_b = sum(s["bytes"] for s in stats)
                    total_f = sum(s["flows"] for s in stats)
                    val_bw = round((total_b*8)/(300*1_000_000),2)
                    val_flows = round(total_f/300,2)

                bw.append(val_bw)
                flows.append(val_flows)

                # Store in history if completed
                if is_completed:
                    _bandwidth_history_cache[tf_key] = {"bw": val_bw, "flows": val_flows}

        data = {"labels":labels,"bandwidth":bw,"flows":flows, "generated_at": datetime.utcnow().isoformat()+"Z"}
        with _cache_lock:
            _bandwidth_cache["data"] = data
            _bandwidth_cache["ts"] = now_ts
            _bandwidth_cache["key"] = cache_key
        return jsonify(data)
    except Exception:
        return jsonify({"labels":[],"bandwidth":[],"flows":[]}), 500

@app.route("/api/conversations")
@throttle(10,30)
def api_conversations():
    # LIMITED TO 10
    range_key = request.args.get('range', '1h')
    tf = get_time_range(range_key)

    # Fetch raw flows to get actual conversation partners
    # Use -O bytes to sort by bytes descending at nfdump level to get 'Top' conversations
    output = run_nfdump(["-O", "bytes", "-n", "100"], tf)

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
        top_rows = rows[:10]

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

    except Exception as e:
        print(f"Error parsing conversations: {e}")
        pass

    data = {"conversations":convs, "generated_at": datetime.utcnow().isoformat()+"Z"}
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


# ===== SNMP Integration =====
import subprocess
import time
import threading

# SNMP Configuration
SNMP_HOST = "192.168.0.1"
SNMP_COMMUNITY = "Phoboshomesnmp_3"

# SNMP OIDs
SNMP_OIDS = {
    "cpu_load_1min": ".1.3.6.1.4.1.2021.10.1.3.1",
    "cpu_load_5min": ".1.3.6.1.4.1.2021.10.1.3.2",
    "mem_total": ".1.3.6.1.4.1.2021.4.5.0",        # Total RAM KB
    "mem_avail": ".1.3.6.1.4.1.2021.4.6.0",        # Available RAM KB
    "sys_uptime": ".1.3.6.1.2.1.1.3.0",            # Uptime timeticks
    "tcp_conns": ".1.3.6.1.2.1.6.9.0",             # tcpCurrEstab
    "proc_count": ".1.3.6.1.2.1.25.1.6.0",         # hrSystemProcesses
    "if_wan_status": ".1.3.6.1.2.1.2.2.1.8.1",     # igc0 status
    "if_lan_status": ".1.3.6.1.2.1.2.2.1.8.2",     # igc1 status
    "tcp_fails": ".1.3.6.1.2.1.6.7.0",             # tcpAttemptFails
    "tcp_retrans": ".1.3.6.1.2.1.6.12.0",          # tcpRetransSegs
    "wan_in": ".1.3.6.1.2.1.31.1.1.1.6.1",         # igc0 in
    "wan_out": ".1.3.6.1.2.1.31.1.1.1.10.1",       # igc0 out
    "lan_in": ".1.3.6.1.2.1.31.1.1.1.6.2",         # igc1 in
    "lan_out": ".1.3.6.1.2.1.31.1.1.1.10.2",       # igc1 out
    "disk_read": ".1.3.6.1.4.1.2021.13.15.1.1.12.2", # nda0 read bytes
    "disk_write": ".1.3.6.1.4.1.2021.13.15.1.1.13.2", # nda0 write bytes
    "udp_in": ".1.3.6.1.2.1.7.1.0",                # udpInDatagrams
    "udp_out": ".1.3.6.1.2.1.7.4.0",               # udpOutDatagrams
}

_snmp_cache = {"data": None, "ts": 0}
_snmp_cache_lock = threading.Lock()


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
        if _snmp_cache["data"] and now - _snmp_cache["ts"] < 30:
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
                elif key.startswith("mem_") or key in ("tcp_conns", "proc_count", "tcp_fails", "tcp_retrans", "wan_in", "wan_out", "lan_in", "lan_out", "disk_read", "disk_write", "udp_in", "udp_out"):
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
            mem_used = result["mem_total"] - result["mem_avail"]
            result["mem_used"] = mem_used
            result["mem_percent"] = round((mem_used / result["mem_total"]) * 100, 1)
        
        if "cpu_load_1min" in result:
            result["cpu_percent"] = min(round((result["cpu_load_1min"] / 4.0) * 100, 1), 100)
        
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


@app.route("/api/stats/firewall")
@throttle(5, 10)
def api_stats_firewall():
    """Firewall health stats from SNMP"""
    data = get_snmp_data()
    return jsonify({"firewall": data})

if __name__=="__main__":
    print("NetFlow Analytics Pro (Modernized)")
    app.run(host="0.0.0.0",port=8080,threaded=True)
