from flask import Flask, render_template_string, jsonify, request
import subprocess, time, os, json, smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
import threading
import concurrent.futures
import requests
import maxminddb
import socket
import gzip
from io import BytesIO
from file_cache import load_file_cached, _json_loader, _list_loader

app = Flask(__name__)

@app.after_request
def compress_response(response):
    if response.status_code < 200 or response.status_code >= 300:
        return response

    accept_encoding = request.headers.get('Accept-Encoding', '')
    if 'gzip' not in accept_encoding.lower():
        return response

    if response.direct_passthrough:
        return response

    content = response.get_data()
    if len(content) < 500:
        return response

    if 'Content-Encoding' in response.headers:
        return response

    gzip_buffer = BytesIO()
    with gzip.GzipFile(mode='wb', fileobj=gzip_buffer) as gzip_file:
        gzip_file.write(content)

    compressed_content = gzip_buffer.getvalue()
    response.set_data(compressed_content)
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(compressed_content)

    return response

# ------------------ Globals & caches ------------------
_cache_lock = threading.RLock()
_stats_cache = {"data": None, "ts": 0}
_bandwidth_cache = {"data": None, "ts": 0}
_conversations_cache = {"data": None, "ts": 0}
_request_times = defaultdict(list)
_throttle_lock = threading.Lock()
_dns_cache, _dns_ttl = {}, {}
_geo_cache = {}
_geo_cache_ttl = 900  # 15 min

_threat_cache = {"data": set(), "mtime": 0}

# Cache for individual bandwidth 5-min intervals
_bw_interval_cache = {}
# Global executor for nfdump calls to limit system load
MAX_WORKERS = 16
DNS_WORKERS = 32
_nfdump_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
_dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=DNS_WORKERS)

# Futures for in-flight bandwidth queries to prevent thundering herd
_bw_futures = {}
# Cache for CSV header parsing
_csv_header_cache = {}

_alert_sent_ts = 0
_alert_history = deque(maxlen=50)

_alert_type_ts = {}
_alert_day_counts = defaultdict(int)
ALERT_TYPE_MIN_INTERVAL = {'threat_ip': 120, 'suspicious_port': 300, 'large_transfer': 300, 'default': 300}
ALERT_DAILY_CAP = 30
ALERT_LOG = '/root/netflow-alerts.log'

_ip_detail_cache = {}
_ip_detail_ttl = 180  # seconds

_threat_status = {'last_attempt':0,'last_ok':0,'size':0,'status':'unknown','error':None}

_metric_nfdump_calls = 0
_metric_stats_cache_hits = 0
_metric_bw_cache_hits = 0
_metric_conv_cache_hits = 0
_metric_http_429 = 0

class NfdumpProcessor:
    @staticmethod
    def run(args, tf=None):
        global _metric_nfdump_calls
        _metric_nfdump_calls += 1
        cmd = ["nfdump","-R","/var/cache/nfdump","-q","-o","csv"]
        if tf: cmd.extend(["-t",tf])
        cmd.extend(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    @staticmethod
    def parse_csv(output):
        # Implementation moved from global scope
        return parse_csv(output) # We will reuse the global function or move it here.
        # For least diff, we can just alias or wrap.
        # But to be clean, let's keep the global function for now as it's used by legacy code if any,
        # or better, replace the global usages.

MMDB_CITY = "/root/GeoLite2-City.mmdb"
MMDB_ASN = "/root/GeoLite2-ASN.mmdb"
THREATLIST_PATH = "/root/threat-ips.txt"
THREAT_FEED_URL_PATH = "/root/threat-feed.url"
THREAT_WHITELIST = "/root/threat-whitelist.txt"
WEBHOOK_PATH = "/root/netflow-webhook.url"
SMTP_CFG_PATH = "/root/netflow-smtp.json"
NOTIFY_CFG_PATH = "/root/netflow-notify.json"

mmdb_city = None
mmdb_asn = None
_threat_thread_started = False
_webhook_session = requests.Session()

PORTS = {20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",3389:"RDP",5900:"VNC",27017:"MongoDB",1194:"OpenVPN",51820:"WireGuard"}
PROTOS = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",51:"AH"}
SUSPICIOUS_PORTS = [4444,5555,6667,8888,9001,9050,9150,31337,12345,1337,666,6666]
INTERNAL_NETS = ["192.168.","10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31."]
INTERNAL_NETS_TUPLE = tuple(INTERNAL_NETS)

DNS_SERVER = "192.168.0.1"
# ------------------ Helpers ------------------

def is_internal(ip):
    return ip.startswith(INTERNAL_NETS_TUPLE)

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
    _geo_cache[ip] = {'ts': now, 'data': res if res else None}
    return _geo_cache[ip]['data']

def throttle(max_calls=5, time_window=10):
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

def resolve_ip(ip):
    now = time.time()
    if ip in _dns_cache and now - _dns_ttl.get(ip, 0) < 300:
        return _dns_cache[ip]
    try:
        # Use socket.gethostbyaddr which is standard and more efficient than subprocess
        # We assume standard resolver configuration
        h, _, _ = socket.gethostbyaddr(ip)
        _dns_cache[ip] = h
        _dns_ttl[ip] = now
        return h
    except Exception:
        pass
    _dns_cache[ip] = None
    _dns_ttl[ip] = now
    return None

def run_nfdump(args, tf=None):
    return NfdumpProcessor.run(args, tf)

def parse_csv(output):
    results = []
    if not output:
        return []

    lines = output.strip().splitlines()
    if not lines:
        return []

    # Dynamic header parsing with caching
    header_line = lines[0]
    indices = _csv_header_cache.get(header_line)

    if indices:
        idx_key, idx_flows, idx_packets, idx_bytes, max_idx = indices
    else:
        header = header_line.lower().split(",")
        idx_key, idx_flows, idx_packets, idx_bytes = -1, -1, -1, -1

        # Heuristics for column names
        for i, col in enumerate(header):
            c = col.strip()
            if idx_key == -1 and c in ('val', 'ip', 'port', 'proto', 'sysid'):
                idx_key = i
            elif idx_flows == -1 and ('flows' in c or ('fl' in c and '%' not in c)) and '%' not in c:
                idx_flows = i
            elif idx_packets == -1 and ('packets' in c or ('pkt' in c and '%' not in c)) and '%' not in c:
                idx_packets = i
            elif idx_bytes == -1 and ('bytes' in c or ('byt' in c and '%' not in c)) and '%' not in c:
                idx_bytes = i

        # Fallback to hardcoded defaults if detection fails
        if idx_key == -1: idx_key = 4
        if idx_flows == -1: idx_flows = 5
        if idx_packets == -1: idx_packets = 7
        if idx_bytes == -1: idx_bytes = 9

        # Determine max index needed
        max_idx = max(idx_key, idx_flows, idx_packets, idx_bytes)

        # Cache the result
        if len(_csv_header_cache) > 100: # Simple limit
            _csv_header_cache.clear()
        _csv_header_cache[header_line] = (idx_key, idx_flows, idx_packets, idx_bytes, max_idx)

    for line in lines[1:]:
        if not line: continue
        parts = line.split(",")
        if len(parts) <= max_idx: continue
        try:
            key = parts[idx_key]
            # Fast skip invalid keys
            if not key or key == "any" or "/" in key: continue

            # nfdump sometimes outputs floats for stats
            bytes_val = int(float(parts[idx_bytes]))

            if bytes_val > 0:
                flows_val = int(float(parts[idx_flows]))
                packets_val = int(float(parts[idx_packets]))
                results.append({"key":key,"bytes":bytes_val,"flows":flows_val,"packets":packets_val})
        except (ValueError, IndexError):
            continue
    return results

def get_traffic_direction(ip, tf):
    f_out = _nfdump_executor.submit(run_nfdump, ["-a",f"src ip {ip}","-s","srcip/bytes","-n","1"], tf)
    f_in = _nfdump_executor.submit(run_nfdump, ["-a",f"dst ip {ip}","-s","dstip/bytes","-n","1"], tf)
    out_parsed = parse_csv(f_out.result())
    in_parsed = parse_csv(f_in.result())
    upload = out_parsed[0]["bytes"] if out_parsed else 0
    download = in_parsed[0]["bytes"] if in_parsed else 0
    return {"upload": upload, "download": download, "ratio": round(upload/download, 2) if download > 0 else 0}

def load_list(path):
    return load_file_cached(path, _list_loader, default=set())


def load_threatlist():
    try:
        mtime = os.path.getmtime(THREATLIST_PATH)
    except FileNotFoundError:
        _threat_cache["data"] = set(); _threat_cache["mtime"] = 0; return set()
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
        if not os.path.exists(THREAT_FEED_URL_PATH):
            _threat_status['status'] = 'missing'
            return
        with open(THREAT_FEED_URL_PATH,'r') as f:
            url = f.read().strip()
        if not url:
            _threat_status['status'] = 'missing'
            return
        r = requests.get(url, timeout=25)
        if r.status_code != 200:
            _threat_status['status'] = 'error'
            _threat_status['error'] = f"HTTP {r.status_code}"
            return
        data = [line.strip() for line in r.text.split('\n') if line.strip() and not line.startswith('#')]
        if not data:
            _threat_status['status'] = 'empty'
            _threat_status['size'] = 0
            return
        tmp_path = THREATLIST_PATH + '.tmp'
        with open(tmp_path,'w') as f:
            f.write('\n'.join(data))
        os.replace(tmp_path, THREATLIST_PATH)
        _threat_status['last_ok'] = time.time()
        _threat_status['size'] = len(data)
        _threat_status['status'] = 'ok'
        _threat_status['error'] = None
    except Exception as e:
        _threat_status['status'] = 'error'
        _threat_status['error'] = str(e)

def get_feed_label():
    try:
        if not os.path.exists(THREAT_FEED_URL_PATH):
            return "threat-feed"
        with open(THREAT_FEED_URL_PATH,'r') as f:
            url = f.read().strip()
        if not url:
            return "threat-feed"
        u = url.lower()
        if 'feodotracker' in u:
            return 'FeodoTracker'
        if 'threatfox' in u:
            return 'ThreatFox'
        if 'cins' in u:
            return 'CINS Army'
        if 'blocklist' in u:
            return 'Blocklist'
        name = url.split('/')[-1] or url
        return name
    except Exception:
        return "threat-feed"

def start_threat_thread():
    global _threat_thread_started
    if _threat_thread_started:
        return
    _threat_thread_started = True
    def loop():
        while True:
            fetch_threat_feed()
            time.sleep(900)  # 15 minutes
    t = threading.Thread(target=loop, daemon=True)
    t.start()


def detect_anomalies(ports_data, sources_data, threat_set, whitelist, feed_label="threat-feed"):
    alerts = []
    seen = set()
    threat_set = threat_set - whitelist
    for item in ports_data[:15]:
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
    for item in sources_data[:10]:
        if item["bytes"] > 2*1024**3:
            alert_key = f"large_{item['key']}"
            if alert_key not in seen:
                alerts.append({"type":"large_transfer","msg":f"📊 Large transfer from {item['key']}: {fmt_bytes(item['bytes'])}","severity":"medium","feed":"local"})
                seen.add(alert_key)
                if len(alerts) >= 8:
                    break
        if item["key"] in threat_set:
            alert_key = f"threat_{item['key']}"
            if alert_key not in seen:
                alerts.append({"type":"threat_ip","msg":f"🚨 {feed_label} match: {item['key']} ({fmt_bytes(item['bytes'])})","severity":"critical","feed":feed_label})
                seen.add(alert_key)
    return alerts


def fmt_bytes(b):
    if b >= 1024**3: return f"{b/1024**3:.2f} GB"
    elif b >= 1024**2: return f"{b/1024**2:.2f} MB"
    elif b >= 1024: return f"{b/1024:.2f} KB"
    return f"{b} B"


def load_smtp_cfg():
    return load_file_cached(SMTP_CFG_PATH, _json_loader, default=None)

def load_notify_cfg():
    default = {"email": True, "webhook": True, "mute_until": 0}
    cfg = load_file_cached(NOTIFY_CFG_PATH, _json_loader, default=default)
    if cfg is default:
        return default
    return {"email": bool(cfg.get("email", True)), "webhook": bool(cfg.get("webhook", True)), "mute_until": float(cfg.get("mute_until", 0) or 0)}


def save_notify_cfg(cfg):
    try:
        payload = {"email": bool(cfg.get('email', True)), "webhook": bool(cfg.get('webhook', True)), "mute_until": float(cfg.get('mute_until', 0) or 0)}
        with open(NOTIFY_CFG_PATH,'w') as f:
            json.dump(payload, f)
    except Exception:
        pass


def send_email(alerts):
    notify = load_notify_cfg()
    if not notify.get("email", True):
        return
    cfg = load_smtp_cfg()
    if not cfg or not alerts:
        return
    host = cfg.get('host'); port = int(cfg.get('port',25))
    user = cfg.get('user'); pwd = cfg.get('password')
    sender = cfg.get('from'); recipients = cfg.get('to') or []
    if isinstance(recipients,str):
        recipients = [r.strip() for r in recipients.split(',') if r.strip()]
    if not host or not sender or not recipients:
        return
    use_tls = bool(cfg.get('use_tls', False))
    subject = f"NetFlow Alerts ({len(alerts)})"
    lines = [f"Time: {datetime.utcnow().isoformat()}Z","", "Alerts:"]
    for a in alerts:
        feed = a.get('feed','local')
        lines.append(f"- [{a.get('severity','')}] ({feed}) {a.get('msg','')}")
    body = "\n".join(lines)
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    msg.set_content(body)
    try:
        if use_tls:
            with smtplib.SMTP(host, port, timeout=25) as s:
                s.starttls()
                if user and pwd:
                    s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=25) as s:
                if user and pwd:
                    s.login(user, pwd)
                s.send_message(msg)
    except Exception:
        pass


def send_webhook(alerts):
    notify = load_notify_cfg()
    if not notify.get("webhook", True):
        return
    if not os.path.exists(WEBHOOK_PATH):
        return
    if not alerts:
        return
    try:
        with open(WEBHOOK_PATH,"r") as f:
            url = f.read().strip()
        if not url:
            return
        payload = {"ts": datetime.utcnow().isoformat()+'Z', "alerts": alerts}
        _webhook_session.post(url, json=payload, timeout=3)
    except Exception:
        pass


def record_history(alerts):
    if not alerts:
        return
    ts = datetime.utcnow().isoformat()+'Z'
    lines = []
    for a in alerts:
        entry = {"ts": ts, "msg": a.get('msg'), "severity": a.get('severity','info'), "feed": a.get('feed','local')}
        _alert_history.appendleft(entry)
        lines.append(entry)
    try:
        with open(ALERT_LOG, 'a') as f:
            for e in lines:
                f.write(json.dumps(e) + "\n")
    except Exception:
        pass


def _should_deliver(alert):
    cfg = load_notify_cfg()
    now = time.time()
    if cfg.get('mute_until', 0) > now:
        return False
    atype = alert.get('type', 'default')
    last = _alert_type_ts.get(atype, 0)
    min_int = ALERT_TYPE_MIN_INTERVAL.get(atype, ALERT_TYPE_MIN_INTERVAL['default'])
    if now - last < min_int:
        return False
    day_key = f"{datetime.utcnow().date()}_{atype}"
    if _alert_day_counts[day_key] >= ALERT_DAILY_CAP:
        return False
    _alert_type_ts[atype] = now
    _alert_day_counts[day_key] += 1
    return True


def send_notifications(alerts):
    global _alert_sent_ts
    if not alerts:
        return
    filtered = [a for a in alerts if _should_deliver(a)]
    if not filtered:
        return
    now = time.time()
    if now - _alert_sent_ts < 60:
        return  # global throttle 60s
    send_webhook(filtered)
    send_email(filtered)
    record_history(filtered)
    _alert_sent_ts = now

# ------------------ Routes ------------------

@app.route("/")
def index():
    start_threat_thread()
    return render_template_string(HTML)

@app.route("/api/overview")
@throttle(3,10)
def api_overview():
    start_threat_thread()
    now_ts = time.time()
    time_range = request.args.get('range', '1h')

    # Align time to minute for better caching
    now = datetime.now().replace(second=0, microsecond=0)
    minute_ts = int(now.timestamp())

    with _cache_lock:
        cache_key = f"{time_range}_{minute_ts}"
        if _stats_cache.get("key") == cache_key and _stats_cache["data"]:
            global _metric_stats_cache_hits
            _metric_stats_cache_hits += 1
            return jsonify(_stats_cache["data"])

    hours = {"15m":0.25,"30m":0.5,"1h":1,"6h":6,"24h":24}.get(time_range, 1)
    past = now - timedelta(hours=hours)
    tf = f"{past.strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"

    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    feed_label = get_feed_label()

    # Use global executor
    f_src = _nfdump_executor.submit(run_nfdump, ["-s","srcip/bytes/flows/packets","-n","20"], tf)
    f_dst = _nfdump_executor.submit(run_nfdump, ["-s","dstip/bytes/flows/packets","-n","20"], tf)
    f_prt = _nfdump_executor.submit(run_nfdump, ["-s","dstport/bytes/flows","-n","20"], tf)
    f_pro = _nfdump_executor.submit(run_nfdump, ["-s","proto/bytes/flows/packets","-n","10"], tf)

    sources = parse_csv(f_src.result())
    dests = parse_csv(f_dst.result())
    ports = parse_csv(f_prt.result())
    protos_raw = parse_csv(f_pro.result())

    seen = set(); protos = []
    for p in protos_raw:
        if p["key"] not in seen:
            seen.add(p["key"]); protos.append(p)

    sources_int = [s for s in sources if is_internal(s["key"])]
    sources_ext = [s for s in sources if not is_internal(s["key"])]
    dests_int = [d for d in dests if is_internal(d["key"])]
    dests_ext = [d for d in dests if not is_internal(d["key"])]

    tot_b = sum(i["bytes"] for i in sources)
    tot_f = sum(i["flows"] for i in sources)
    tot_p = sum(i["packets"] for i in sources)

    # Enrich all sources and dests to compute ASN/Country stats
    # We resolve DNS only for top 8 to save time, but GeoIP is fast so we do it for all.
    ips_to_resolve = {i["key"] for i in sources[:8]} | {i["key"] for i in dests[:8]}
    resolved = {}
    if ips_to_resolve:
        # Use dedicated executor for DNS resolution
        future_to_ip = {_dns_executor.submit(resolve_ip, ip): ip for ip in ips_to_resolve}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            resolved[ip] = future.result()

    asn_stats = defaultdict(lambda: {"bytes":0, "flows":0, "as_org": "Unknown"})
    country_stats = defaultdict(lambda: {"bytes":0, "flows":0, "code": "XX", "flag": ""})

    for i in sources:
        i["internal"] = is_internal(i["key"])
        i["region"] = get_region(i["key"])
        i["hostname"] = resolved.get(i["key"]) if i["key"] in resolved else None

        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})

            # Aggregation
            if not i["internal"]:
                asn_num = geo.get("asn")
                if asn_num:
                    k = f"AS{asn_num}"
                    asn_stats[k]["bytes"] += i["bytes"]
                    asn_stats[k]["flows"] += i["flows"]
                    asn_stats[k]["as_org"] = geo.get("asn_org") or k

                iso = geo.get("country_iso")
                if iso:
                    country_stats[iso]["bytes"] += i["bytes"]
                    country_stats[iso]["flows"] += i["flows"]
                    country_stats[iso]["code"] = iso
                    country_stats[iso]["flag"] = geo.get("flag")
                    country_stats[iso]["name"] = geo.get("country")

        i["threat"] = i["key"] in threat_set and i["key"] not in whitelist

    for i in dests:
        i["internal"] = is_internal(i["key"])
        i["region"] = get_region(i["key"])
        i["hostname"] = resolved.get(i["key"]) if i["key"] in resolved else None
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})

            if not i["internal"]:
                asn_num = geo.get("asn")
                if asn_num:
                    k = f"AS{asn_num}"
                    asn_stats[k]["bytes"] += i["bytes"]
                    asn_stats[k]["flows"] += i["flows"]
                    asn_stats[k]["as_org"] = geo.get("asn_org") or k

                iso = geo.get("country_iso")
                if iso:
                    country_stats[iso]["bytes"] += i["bytes"]
                    country_stats[iso]["flows"] += i["flows"]
                    country_stats[iso]["code"] = iso
                    country_stats[iso]["flag"] = geo.get("flag")
                    country_stats[iso]["name"] = geo.get("country")

        i["threat"] = i["key"] in threat_set and i["key"] not in whitelist

    top_asns = sorted([{"asn":k, **v} for k,v in asn_stats.items()], key=lambda x: x["bytes"], reverse=True)[:10]
    top_countries = sorted([{"iso":k, **v} for k,v in country_stats.items()], key=lambda x: x["bytes"], reverse=True)[:10]

    for i in ports:
        try:
            port = int(i["key"])
            i["service"] = PORTS.get(port, "Unknown")
            i["suspicious"] = port in SUSPICIOUS_PORTS
        except Exception:
            i["service"] = "Unknown"; i["suspicious"] = False

    for i in protos:
        try:
            proto = int(i["key"])
            i["proto_name"] = PROTOS.get(proto, f"Proto-{i['key']}")
        except Exception:
            i["proto_name"] = i["key"]

    alerts = detect_anomalies(ports, sources, threat_set, whitelist, feed_label)
    send_notifications([a for a in alerts if a.get("severity") in ("critical","high")])

    feed_ts = None
    try:
        feed_ts = datetime.utcfromtimestamp(os.path.getmtime(THREATLIST_PATH)).isoformat()+"Z"
    except Exception:
        pass

    data = {
        "top_sources":sources[:10],"top_destinations":dests[:10],
        "sources_internal":sources_int[:10],"sources_external":sources_ext[:10],
        "dests_internal":dests_int[:10],"dests_external":dests_ext[:10],
        "top_ports":ports[:15],"protocols":protos[:6],
        "top_asns": top_asns,
        "top_countries": top_countries,
        "alerts":alerts[:10],
        "totals":{"bytes":tot_b,"flows":tot_f,"packets":tot_p,"bytes_fmt":fmt_bytes(tot_b),"avg_packet_size":int(tot_b/tot_p) if tot_p > 0 else 0},
        "time_range":time_range,
        "notify": load_notify_cfg(),
        "threat_feed_updated": feed_ts,
        "threat_status": _threat_status,
        "feed_label": feed_label
    }

    with _cache_lock:
        _stats_cache["data"] = data; _stats_cache["key"] = cache_key; _stats_cache["ts"] = now_ts
    return jsonify(data)

@app.route("/api/bandwidth")
@throttle(10,20)
def api_bandwidth():
    # Optimization: Use fixed 5-minute intervals (aligned to clock)
    # This allows caching past intervals indefinitely.

    now = datetime.now()
    # Align to next 5-minute boundary to determine current unfinished bucket
    # e.g. 12:03 -> next is 12:05. Current bucket is 12:00-12:05
    minute_aligned = (now.minute // 5) * 5 + 5
    ref_time = now.replace(minute=0, second=0, microsecond=0) + timedelta(minutes=minute_aligned)

    # We want 12 buckets ending at ref_time
    # i=0: ref_time-5m to ref_time (Current bucket)
    # i=1: ref_time-10m to ref_time-5m

    intervals_to_fetch = []
    cached_results = {}

    # Identify which intervals are missing from cache
    for i in range(12):
        et = ref_time - timedelta(minutes=i*5)
        st = et - timedelta(minutes=5)

        # Cache key based on start/end
        key = f"{st.strftime('%Y%m%d%H%M')}-{et.strftime('%Y%m%d%H%M')}"

        # Check if this interval is in the past (completed)
        is_past = et < now

        with _cache_lock:
            cached = _bw_interval_cache.get(key)
            # If cached and (it's a past interval OR it's a current interval cached <60s ago)
            if cached and (is_past or (time.time() - cached['ts'] < 60)):
                cached_results[i] = cached['data']
                continue

            # Check if there is already a pending future for this key
            pending = _bw_futures.get(key)
            if pending:
                # Add to futures list to wait for, but associate with current loop index 'i'
                # We can't easily attach 'i' to the existing future without wrapping it,
                # but we can just wait for it and use its result if we structure the result correctly.
                # However, futures list below expects to yield (i, key, data, is_past).
                # The pending future already returns that structure.
                # We just need to make sure we handle the index 'i' correctly if it was different?
                # Actually, the key uniquely identifies the time range. 'i' is just the position in the current response list.
                # The pending future returns 'i' from the *original* request context.
                # If we rely on that 'i', it might be wrong for *this* request (though likely same if aligned).
                # To be safe, we wrap it or handle it.
                # But since we use fixed 12 intervals from ref_time, and ref_time is aligned to 5m,
                # 'i' corresponds to the same time range for everyone seeing the same 'ref_time'.
                pass # Logic below handles it

        intervals_to_fetch.append((i, st, et, key, is_past))

    # Fetch missing intervals
    if intervals_to_fetch:
        def fetch_one(args):
            i, st, et, key, is_past = args
            tf = f"{st.strftime('%Y/%m/%d.%H:%M:%S')}-{et.strftime('%Y/%m/%d.%H:%M:%S')}"
            out = run_nfdump(["-s","proto/bytes/flows","-n","1"], tf)
            stats = parse_csv(out)
            # Process stats immediately
            b_val, f_val = 0, 0
            if stats:
                total_b = sum(s["bytes"] for s in stats)
                total_f = sum(s["flows"] for s in stats)
                b_val = round((total_b*8)/(300*1_000_000),2)
                f_val = round(total_f/300,2)

            result_data = {"label": et.strftime("%H:%M"), "bw": b_val, "flows": f_val}
            return (key, result_data, is_past)

        futures_map = {} # future -> i

        for args in intervals_to_fetch:
            i, st, et, key, is_past = args
            with _cache_lock:
                # Check pending again under lock
                if key in _bw_futures:
                    f = _bw_futures[key]
                else:
                    f = _nfdump_executor.submit(fetch_one, args)
                    _bw_futures[key] = f

                    # Remove from _bw_futures when done
                    def cleanup(ft):
                        with _cache_lock:
                            if _bw_futures.get(key) == ft:
                                del _bw_futures[key]
                    f.add_done_callback(cleanup)

            futures_map[f] = i

        for f in concurrent.futures.as_completed(futures_map.keys()):
            try:
                key, data, is_past = f.result()
                i = futures_map[f]
                cached_results[i] = data
                # Update cache
                with _cache_lock:
                    _bw_interval_cache[key] = {"data": data, "ts": time.time()}
            except Exception:
                pass

    # Assemble response (reverse order: oldest to newest)
    labels, bw, flows = [], [], []
    for i in range(11, -1, -1):
        res = cached_results.get(i, {"label": "", "bw": 0, "flows": 0})
        labels.append(res["label"])
        bw.append(res["bw"])
        flows.append(res["flows"])

    return jsonify({"labels":labels,"bandwidth":bw,"flows":flows, "generated_at": datetime.utcnow().isoformat()+"Z"})

@app.route("/api/conversations")
@throttle(10,30)
def api_conversations():
    now_ts = time.time()
    with _cache_lock:
        if _conversations_cache["data"] and now_ts - _conversations_cache["ts"] < 60:
            global _metric_conv_cache_hits
            _metric_conv_cache_hits += 1
            return jsonify(_conversations_cache["data"])
    now = datetime.now().replace(second=0, microsecond=0)
    tf = f"{(now-timedelta(hours=1)).strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"
    try:
        f_src = _nfdump_executor.submit(run_nfdump, ["-s","srcip/bytes","-n","15"], tf)
        f_dst = _nfdump_executor.submit(run_nfdump, ["-s","dstip/bytes","-n","15"], tf)
        src_data = parse_csv(f_src.result())
        dst_data = parse_csv(f_dst.result())

        convs = []
        for i, src in enumerate(src_data[:15]):
            if i < len(dst_data):
                convs.append({
                    "src":src["key"],"dst":dst_data[i]["key"],
                    "bytes":src["bytes"],"bytes_fmt":fmt_bytes(src["bytes"]),
                    "src_region":get_region(src["key"]),
                    "dst_region":get_region(dst_data[i]["key"])
                })
        data = {"conversations":convs, "generated_at": datetime.utcnow().isoformat()+"Z"}
        with _cache_lock:
            _conversations_cache["data"] = data; _conversations_cache["ts"] = now_ts
        return jsonify(data)
    except Exception:
        with _cache_lock:
            if _conversations_cache.get("data"):
                return jsonify(_conversations_cache["data"])
        return jsonify({"conversations":[]}), 500

@app.route("/api/ip_detail/<ip>")
@throttle(5,10)
def api_ip_detail(ip):
    start_threat_thread()
    now = time.time()
    # cache
    if ip in _ip_detail_cache and now - _ip_detail_cache[ip]['ts'] < _ip_detail_ttl:
        return jsonify(_ip_detail_cache[ip]['data'])
    dt = datetime.now()
    tf = f"{(dt-timedelta(hours=1)).strftime('%Y/%m/%d.%H:%M:%S')}-{dt.strftime('%Y/%m/%d.%H:%M:%S')}"

    # Use global executor
    f_dir = _nfdump_executor.submit(get_traffic_direction, ip, tf)
    f_src = _nfdump_executor.submit(run_nfdump, ["-s","dstport/bytes/flows","-n","10","-a",f"src ip {ip}"], tf)
    f_dst = _nfdump_executor.submit(run_nfdump, ["-s","srcport/bytes/flows","-n","10","-a",f"dst ip {ip}"], tf)
    f_pro = _nfdump_executor.submit(run_nfdump, ["-s","proto/bytes/packets","-n","5","-a",f"ip {ip}"], tf)
    f_dns = _dns_executor.submit(resolve_ip, ip)

    direction = f_dir.result()
    src_ports = parse_csv(f_src.result())
    dst_ports = parse_csv(f_dst.result())
    protocols = parse_csv(f_pro.result())
    hostname = f_dns.result()
    for p in protocols:
        try:
            proto = int(p["key"]); p["proto_name"] = PROTOS.get(proto, f"Proto-{p['key']}")
        except Exception:
            p["proto_name"] = p["key"]
    for p in src_ports + dst_ports:
        try:
            port = int(p["key"]); p["service"] = PORTS.get(port, "Unknown")
        except Exception:
            p["service"] = "Unknown"
    geo = lookup_geo(ip)
    data = {
        "ip": ip,
        "hostname": hostname,
        "region": get_region(ip),
        "internal": is_internal(ip),
        "geo": geo,
        "direction": direction,
        "src_ports": src_ports[:10],
        "dst_ports": dst_ports[:10],
        "protocols": protocols,
        "threat": ip in load_threatlist() and ip not in load_list(THREAT_WHITELIST)
    }
    _ip_detail_cache[ip] = {"ts": now, "data": data}
    return jsonify(data)

@app.route("/api/export")
def export_csv():
    data = api_overview().get_json()
    csv_lines = ["Type,IP/Port,Traffic,Flows\n"]
    for src in data.get("top_sources",[])[:10]:
        csv_lines.append(f"Source,{src['key']},{src['bytes']},{src['flows']}\n")
    return "".join(csv_lines), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=netflow_export.csv'}

@app.route("/api/export_json")
def export_json():
    data = api_overview().get_json()
    return jsonify(data)

@app.route("/api/test_alert")
@throttle(2,30)
def api_test_alert():
    alert = {"severity":"critical","msg":"TEST ALERT triggered from UI","feed":"local"}
    send_notifications([alert])
    return jsonify({"status":"ok","sent":True})

@app.route('/api/threat_refresh', methods=['POST'])
@throttle(10,20)
def api_threat_refresh():
    global _last_feed_manual
    now = time.time()
    if now - _last_feed_manual < 300:
        return jsonify({"status":"throttled","next_in": int(300 - (now - _last_feed_manual))}), 429
    _last_feed_manual = now
    fetch_threat_feed()
    return jsonify({"status":"ok","threat_status": _threat_status})

@app.route("/api/notify_status")
@throttle(5,10)
def api_notify_status():
    return jsonify(load_notify_cfg())

@app.route("/api/notify_toggle", methods=['POST'])
@throttle(5,10)
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
@throttle(5,10)
def api_alerts_history():
    return jsonify(list(_alert_history))


def read_alert_log(days=7):
    out = []
    cutoff = datetime.utcnow() - timedelta(days=days)
    if not os.path.exists(ALERT_LOG):
        return out
    try:
        with open(ALERT_LOG,'r') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    obj=json.loads(line)
                    ts = obj.get('ts')
                    if ts:
                        try:
                            dt=datetime.fromisoformat(ts.replace('Z',''))
                            if dt < cutoff:
                                continue
                        except Exception:
                            pass
                    out.append(obj)
                except Exception:
                    continue
    except Exception:
        pass
    return out


@app.route('/api/alerts_export')
@throttle(10,20)
def api_alerts_export():
    fmt = request.args.get('format','json').lower()
    data = read_alert_log()
    if fmt == 'csv':
        lines=["ts,severity,feed,msg\n"]
        for a in data:
            msg = (a.get('msg','') or '').replace('"','').replace('\n',' ')
            lines.append(f"{a.get('ts','')},{a.get('severity','')},{a.get('feed','')},\"{msg}\"\n")
        return ''.join(lines),200,{'Content-Type':'text/csv','Content-Disposition':'attachment; filename=alerts.csv'}
    return jsonify({"alerts": data})



@app.route('/api/notify_mute', methods=['POST'])
@throttle(3,10)
def api_notify_mute():
    payload = request.get_json(force=True, silent=True) or {}
    minutes = float(payload.get('minutes', 60) or 60)
    mute = bool(payload.get('mute', True))
    cfg = load_notify_cfg()
    if mute:
        cfg['mute_until'] = time.time() + minutes*60
    else:
        cfg['mute_until'] = 0
    save_notify_cfg(cfg)
    return jsonify(cfg)


@app.route('/healthz')
def healthz():
    return jsonify({"status":"ok","threat_status":_threat_status})


@app.route('/metrics')
def metrics():
    lines = [
        f"netflow_nfdump_calls_total {_metric_nfdump_calls}",
        f"netflow_stats_cache_hits_total {_metric_stats_cache_hits}",
        f"netflow_bw_cache_hits_total {_metric_bw_cache_hits}",
        f"netflow_conversations_cache_hits_total {_metric_conv_cache_hits}",
        f"netflow_rate_limited_total {_metric_http_429}",
        f"threat_feed_size {_threat_status.get('size',0)}",
    ]
    return "\n".join(lines)+"\n", 200, {'Content-Type':'text/plain'}

# ------------------ HTML ------------------

HTML = '''<!DOCTYPE html>
<html><head><title>NetFlow Analytics</title><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#000000;--card:#0d0d0d;--border:#00ff41;--text:#00ff41;--accent:#39ff14;--accent2:#00ff41;--badge:#1a1a1a;--badge-text:#39ff14;--warn:#ffff00;--danger:#ff0040}
[data-theme="dark"]{--bg:#0a0a0a;--card:#1a1a1a;--border:#2a2a2a;--text:#e0e0e0;--accent:#667eea;--accent2:#764ba2;--badge:#2a4a7c;--badge-text:#64b5f6}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);padding:10px;transition:all 0.3s}
.container{max-width:1900px;margin:0 auto}
.controls{display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap;align-items:center}
.controls select,.controls button{background:var(--card);color:var(--text);border:1px solid var(--border);padding:8px 12px;border-radius:6px;cursor:pointer;font-size:0.9em}
.controls button:hover{background:var(--accent);color:#000;box-shadow:0 0 15px var(--accent)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:12px}
.card{background:var(--card);border-radius:8px;padding:12px;border:1px solid var(--border);position:relative;box-shadow:0 0 10px rgba(0,255,65,0.2)}
.card.collapsible .card-header{cursor:pointer;user-select:none}
.card.collapsible .card-header:after{content:'▼';float:right;transition:transform 0.3s}
.card.collapsed .card-header:after{transform:rotate(-90deg)}
.card.collapsed .card-body{display:none}
.card h2{color:var(--accent);margin-bottom:10px;font-size:1.1em;border-bottom:1px solid var(--border);padding-bottom:8px;text-shadow:0 0 10px var(--accent)}
.stat-box{background:linear-gradient(135deg,#000000,#0d0d0d);border:2px solid var(--accent);color:var(--accent);box-shadow:0 0 20px rgba(57,255,20,0.3);padding:15px;border-radius:6px;text-align:center}
.stat-box .value{font-size:1.8em;font-weight:bold}
.stat-box .label{font-size:0.85em;opacity:0.9;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:0.85em}
th{background:var(--card);padding:8px;text-align:left;font-weight:600;color:var(--accent);border-bottom:1px solid var(--accent);position:sticky;top:0}
td{padding:6px 8px;border-bottom:1px solid var(--border)}
tr:hover{background:var(--border);cursor:pointer}
.badge{display:inline-block;padding:3px 6px;border-radius:4px;font-size:0.8em;font-weight:600;background:var(--badge);color:var(--badge-text)}
.badge.suspicious{background:var(--danger);color:#fff}
.badge.internal{background:#1a4a1a;color:#86efac}
.badge.external{background:#4a1a1a;color:#fca5a5}
.badge.threat{background:var(--danger);color:#fff;font-weight:800}
.hostname{color:var(--badge-text);font-size:0.8em;display:block}
.region{font-size:0.75em;opacity:0.7}
.flag{font-size:0.95em;margin-left:4px}
.chart-container{position:relative;height:250px;margin-top:10px}
.wide-card{grid-column:1/-1}
.loading{text-align:center;color:#666;padding:15px}
.update-time{text-align:center;color:#666;margin-top:15px;font-size:0.8em}
.arrow{color:var(--accent);font-weight:bold}
.alert-box{background:#451a03;border-left:4px solid var(--warn);padding:10px;margin:5px 0;border-radius:4px;font-size:0.85em}
.alert-box.high{border-color:var(--danger);background:#450a0a}
.alert-box.critical{border-color:var(--danger);background:#370000}
.fullscreen{position:fixed;top:0;left:0;right:0;bottom:0;z-index:9999;background:var(--bg);padding:20px;overflow:auto}
.fullscreen-btn{position:absolute;top:10px;right:10px;background:var(--accent);color:#fff;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:0.8em}
.search-box{width:200px;padding:8px;background:var(--card);border:1px solid var(--border);border-radius:6px;color:var(--text)}
.modal{display:none;position:fixed;z-index:10000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.8)}
.modal-content{background:var(--card);margin:5% auto;padding:20px;border:2px solid var(--accent);border-radius:8px;width:90%;max-width:800px;max-height:80vh;overflow:auto}
.close-modal{float:right;font-size:28px;font-weight:bold;cursor:pointer;color:var(--accent)}
.close-modal:hover{color:var(--danger)}
.ip-clickable{cursor:pointer;text-decoration:underline;text-decoration-style:dotted}
.ip-clickable:hover{color:var(--accent)}
.select-sm{padding:6px 8px;font-size:0.85em;background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:6px;}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:12px;background:var(--card);border:1px solid var(--border);font-size:0.8em}.pill.ok{color:#10b981;border-color:#10b981}.pill.warn{color:#f59e0b;border-color:#f59e0b}.pill.err{color:#ef4444;border-color:#ef4444}
</style>
</head><body>
<div class="container">
<div class="controls">
<select id="timeRange" onchange="changeTimeRange()">
<option value="15m">Last 15 min</option>
<option value="30m">Last 30 min</option>
<option value="1h" selected>Last Hour</option>
<option value="6h">Last 6 Hours</option>
<option value="24h">Last 24 Hours</option>
</select>
<input type="text" id="searchBox" class="search-box" placeholder="Search IP..." onkeyup="filterIPs()">
<select id="refreshSelect" onchange="changeRefresh()">
<option value="10000">Auto: 10s</option>
<option value="30000" selected>Auto: 30s</option>
<option value="60000">Auto: 60s</option>
<option value="120000">Auto: 120s</option>
</select>
<button id="pauseBtn" onclick="togglePause()">Pause</button>
<button onclick="toggleTheme()">Toggle Theme</button>
<button onclick="exportCSV()">Export CSV</button>
<button onclick="exportJSON()">Export JSON</button>
<button onclick="exportAlerts('json')">Alerts JSON</button>
<button onclick="exportAlerts('csv')">Alerts CSV</button>
<button onclick="sendTestAlert()">Send Test Alert</button>
<button onclick="toggleNotify('email')" id="emailBtn">Email: ...</button>
<button onclick="toggleNotify('webhook')" id="webhookBtn">Webhook: ...</button>
<button onclick="muteAlerts()" id="muteBtn">Mute 1h</button>
<button onclick="refreshFeed()" id="feedRefreshBtn">Refresh Feed</button>
<button onclick="toggleFullscreen('bwCard')">📊 Fullscreen</button>
<span id="feedStatus" class="pill" style="margin-left:auto;"></span>
<span id="limitStatus" class="pill warn" style="display:none;"></span>
<span style="opacity:0.7" id="lastUpdate">-</span>
</div>

<div id="alertsContainer"></div>

<div class="grid">
<div class="card"><div class="stat-box"><div class="value" id="totalTraffic">...</div><div class="label">Total Traffic</div></div></div>
<div class="card"><div class="stat-box"><div class="value" id="totalFlows">...</div><div class="label">Flows</div></div></div>
<div class="card"><div class="stat-box"><div class="value" id="avgPacketSize">...</div><div class="label">Avg Packet</div></div></div>
</div>

<div class="card wide-card" id="bwCard">
<button class="fullscreen-btn" onclick="toggleFullscreen('bwCard')">⛶</button>
<h2>📊 Bandwidth & Flow Rate</h2>
<div class="chart-container"><canvas id="bwChart"></canvas></div>
</div>

<div class="grid">
<div class="card collapsible" id="cardSources"><div class="card-header" onclick="toggleCard(this)"><h2>🔝 Top Sources</h2></div><div class="card-body">
<table id="topSources"><thead><tr><th>IP</th><th>Traffic</th></tr></thead><tbody><tr><td colspan="2" class="loading">Loading...</td></tr></tbody></table>
</div></div>

<div class="card collapsible" id="cardDests"><div class="card-header" onclick="toggleCard(this)"><h2>🎯 Top Destinations</h2></div><div class="card-body">
<table id="topDests"><thead><tr><th>IP</th><th>Traffic</th></tr></thead><tbody><tr><td colspan="2" class="loading">Loading...</td></tr></tbody></table>
</div></div>

<div class="card collapsible" id="cardPorts"><div class="card-header" onclick="toggleCard(this)"><h2>🔌 Top Ports</h2></div><div class="card-body">
<table id="topPorts"><thead><tr><th>Port</th><th>Service</th><th>Traffic</th></tr></thead><tbody><tr><td colspan="3" class="loading">Loading...</td></tr></tbody></table>
</div></div>

<div class="card collapsible" id="cardProtocols"><div class="card-header" onclick="toggleCard(this)"><h2>📡 Protocols</h2></div><div class="card-body">
<table id="protocols"><thead><tr><th>Protocol</th><th>Traffic</th><th>Flows</th></tr></thead><tbody><tr><td colspan="3" class="loading">Loading...</td></tr></tbody></table>
</div></div>

<div class="card collapsible" id="cardCountries"><div class="card-header" onclick="toggleCard(this)"><h2>🌍 Top Countries</h2></div><div class="card-body">
<table id="topCountries"><thead><tr><th>Country</th><th>Traffic</th></tr></thead><tbody><tr><td colspan="2" class="loading">Loading...</td></tr></tbody></table>
</div></div>

<div class="card collapsible" id="cardASNs"><div class="card-header" onclick="toggleCard(this)"><h2>🏢 Top ASNs</h2></div><div class="card-body">
<table id="topASNs"><thead><tr><th>ASN</th><th>Org</th><th>Traffic</th></tr></thead><tbody><tr><td colspan="3" class="loading">Loading...</td></tr></tbody></table>
</div></div>
</div>

<div class="card wide-card collapsible" id="cardConversations"><div class="card-header" onclick="toggleCard(this)"><h2>💬 Top Conversations</h2></div><div class="card-body">
<table id="conversations"><thead><tr><th>Source</th><th></th><th>Destination</th><th>Traffic</th></tr></thead><tbody><tr><td colspan="4" class="loading">Loading...</td></tr></tbody></table>
</div></div>

<div class="card wide-card collapsible" id="cardAlerts"><div class="card-header" onclick="toggleCard(this)"><h2>📜 Recent Alerts</h2></div><div class="card-body">
<table id="alertsHistory"><thead><tr><th>Time</th><th>Severity</th><th>Feed</th><th>Message</th></tr></thead><tbody><tr><td colspan="4" class="loading">Loading...</td></tr></tbody></table>
</div></div>

</div>

<div id="ipModal" class="modal">
<div class="modal-content">
<span class="close-modal" onclick="closeModal()">&times;</span>
<h2 id="modalTitle">IP Details</h2>
<div id="modalBody"></div>
</div>
</div>

<script>
let chart=null,currentTheme='green';
let refreshMs=parseInt(localStorage.getItem('refreshMs')||30000);
let timer=null; let paused=false;
let collapsedCards=new Set(JSON.parse(localStorage.getItem('collapsedCards')||'[]'));
let limited=false;
let lastLimitedTs=0;

if(localStorage.getItem('theme')){
    currentTheme=localStorage.getItem('theme');
    document.body.dataset.theme=currentTheme;
}

function schedule(){ if(timer) clearInterval(timer); if(!paused){ timer=setInterval(update, refreshMs);} }

function changeRefresh(){
    const val=parseInt(document.getElementById('refreshSelect').value);
    refreshMs=val; localStorage.setItem('refreshMs', refreshMs); schedule();
}

function togglePause(){
    paused=!paused;
    const btn=document.getElementById('pauseBtn');
    if(paused){ if(timer) clearInterval(timer); btn.textContent='Resume'; document.getElementById('lastUpdate').textContent='Paused'; }
    else { btn.textContent='Pause'; update(); schedule(); }
}

function changeTimeRange(){
    const val=document.getElementById('timeRange').value;
    localStorage.setItem('timeRange', val);
    update();
}
function toggleTheme(){
    currentTheme=currentTheme=='green'?'dark':'green';
    localStorage.setItem('theme',currentTheme);
    document.body.dataset.theme=currentTheme;
    if(chart)chart.destroy(); chart=null; update();
}
function exportCSV(){window.location.href='/api/export'}
function exportJSON(){window.location.href='/api/export_json'}
function sendTestAlert(){fetch('/api/test_alert').then(r=>r.json()).then(()=>alert('Test alert sent (check email/webhook)')).catch(console.error)}

async function loadNotifyStatus(){
    try{
        const r=await fetch('/api/notify_status');
        const d=await r.json();
        updateNotifyButtons(d);
    }catch(e){console.error(e)}
}

function updateNotifyButtons(d){
    notifyState=d;
    const eb=document.getElementById('emailBtn');
    const wb=document.getElementById('webhookBtn');
    const mb=document.getElementById('muteBtn');
    eb.textContent='Email: '+(d.email?'ON':'OFF');
    wb.textContent='Webhook: '+(d.webhook?'ON':'OFF');
    const now=Date.now()/1000;
    const muted = d.mute_until && d.mute_until > now;
    mb.textContent = muted? 'Unmute' : 'Mute 1h';
}

function updateFeedStatus(st){
    const el=document.getElementById('feedStatus');
    if(!el) return;
    if(!st){el.textContent='';return;}
    let cls='pill ok'; let txt='Feed ok';
    if(st.status==='error'){cls='pill err'; txt='Feed error';}
    else if(st.status==='missing'){cls='pill warn'; txt='Feed missing';}
    else if(st.status==='empty'){cls='pill warn'; txt='Feed empty (0 IPs)';}
    else if(st.status!=='ok'){cls='pill warn'; txt=st.status||'unknown';}
    const age = st.last_ok?` • ${(Math.floor((Date.now()/1000 - st.last_ok)/60))}m ago`:'';
    const size = st.size?` • ${st.size} IPs`:'';
    el.className=cls; el.textContent=`${txt}${size}${age}`;
}


function fetchJson(url, options={}, retries=2, backoff=500){
    return new Promise(async (resolve, reject)=>{
        for(let i=0;i<=retries;i++){
            try{
                const resp = await fetch(url, options);
                if(resp.status===429){
                    limited=true; lastLimitedTs=Date.now();
                    updateLimitStatus(true);
                    throw new Error('HTTP 429');
                }
                if(!resp.ok) throw new Error('HTTP '+resp.status);
                const data = await resp.json();
                return resolve(data);
            }catch(e){
                if(i===retries) return reject(e);
                const jitter = Math.floor(Math.random()*200);
                await new Promise(res=>setTimeout(res, backoff*Math.pow(2,i)+jitter));
            }
        }
    });
}


function updateLimitStatus(limitedFlag){
    const el=document.getElementById('limitStatus');
    if(!el) return;
    if(limitedFlag){
        el.style.display='inline-flex';
        el.textContent='Rate limited';
    } else {
        el.style.display='none';
    }
}

async function toggleNotify(target){
    try{
        const current = target==='email'?document.getElementById('emailBtn').textContent.includes('ON'):
                        document.getElementById('webhookBtn').textContent.includes('ON');
        const body={target:target,state:!current};
        const r=await fetch('/api/notify_toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const d=await r.json();
        updateNotifyButtons(d);
    }catch(e){console.error(e)}
}

function toggleFullscreen(id){document.getElementById(id).classList.toggle('fullscreen')}
function toggleCard(el){const card=el.parentElement;card.classList.toggle('collapsed');if(card.id){if(card.classList.contains('collapsed'))collapsedCards.add(card.id);else collapsedCards.delete(card.id);localStorage.setItem('collapsedCards',JSON.stringify(Array.from(collapsedCards)));}}
function filterIPs(){const q=document.getElementById('searchBox').value.toLowerCase();document.querySelectorAll('table tbody tr').forEach(r=>{const txt=r.textContent.toLowerCase();r.style.display=txt.includes(q)?'':'none'})}

function exportAlerts(fmt){window.location.href='/api/alerts_export?format='+fmt;}

async function muteAlerts(){
    try{
        const now=Date.now()/1000;
        const muted = notifyState && notifyState.mute_until && notifyState.mute_until > now;
        const body = muted?{mute:false}:{mute:true, minutes:60};
        const r = await fetch('/api/notify_mute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const d = await r.json();
        notifyState=d; updateNotifyButtons(d);
    }catch(e){console.error(e)}
}

function applyCollapsed(){
    document.querySelectorAll('.card.collapsible').forEach(c=>{
        if(c.id && collapsedCards.has(c.id)) c.classList.add('collapsed');
    });
}

function loadStoredUI(){
    const tr=localStorage.getItem('timeRange');
    if(tr){const sel=document.getElementById('timeRange'); if(sel && sel.querySelector(`option[value="${tr}"]`)) sel.value=tr;}
    applyCollapsed();
}

async function showIPDetail(ip){
    try{
        const r=await fetch('/api/ip_detail/'+ip);
        const d=await r.json();
        const fmt=b=>b>=1024**3?(b/1024**3).toFixed(2)+' GB':b>=1024**2?(b/1024**2).toFixed(2)+' MB':b>=1024?(b/1024).toFixed(2)+' KB':b+' B';
        const flag=d.geo&&d.geo.flag?`<span class="flag">${d.geo.flag}</span>`:'';
        const city=d.geo&&d.geo.city?` (${d.geo.city})`:'';
        const asn=d.geo&&d.geo.asn?`ASN ${d.geo.asn} ${d.geo.asn_org||''}`:'';
        document.getElementById('modalTitle').textContent='Details: '+ip;
        document.getElementById('modalBody').innerHTML=`
            <p><strong>Hostname:</strong> ${d.hostname||'N/A'}</p>
            <p><strong>Region:</strong> ${d.region} ${flag} ${city}</p>
            <p><strong>ASN:</strong> ${asn||'N/A'}</p>
            <p><strong>Type:</strong> <span class="badge ${d.internal?'internal':'external'}">${d.internal?'Internal':'External'}</span> ${d.threat?'<span class="badge threat">THREAT</span>':''}</p>
            <hr style="margin:15px 0;border-color:var(--border)">
            <h3>Traffic Direction</h3>
            <p>⬆️ Upload: <strong>${fmt(d.direction.upload)}</strong></p>
            <p>⬇️ Download: <strong>${fmt(d.direction.download)}</strong></p>
            <p>📊 Ratio: <strong>${d.direction.ratio}</strong></p>
            <hr style="margin:15px 0;border-color:var(--border)">
            <h3>Top Source Ports</h3>
            <table style="margin-top:10px">
            ${d.src_ports.map(p=>'<tr><td>'+p.key+'</td><td>'+p.service+'</td><td>'+fmt(p.bytes)+'</td></tr>').join('')||'<tr><td>No data</td></tr>'}
            </table>
            <h3 style="margin-top:15px">Top Destination Ports</h3>
            <table style="margin-top:10px">
            ${d.dst_ports.map(p=>'<tr><td>'+p.key+'</td><td>'+p.service+'</td><td>'+fmt(p.bytes)+'</td></tr>').join('')||'<tr><td>No data</td></tr>'}
            </table>
            <h3 style="margin-top:15px">Protocols</h3>
            <table style="margin-top:10px">
            ${d.protocols.map(p=>'<tr><td>'+p.proto_name+'</td><td>'+fmt(p.bytes)+'</td><td>'+p.packets+'</td></tr>').join('')||'<tr><td>No data</td></tr>'}
            </table>
        `;
        document.getElementById('ipModal').style.display='block';
    }catch(e){console.error(e)}
}

function closeModal(){document.getElementById('ipModal').style.display='none'}
window.onclick=function(e){if(e.target==document.getElementById('ipModal'))closeModal()}

async function loadAlertsHistory(){
    try{
        const d=await fetchJson('/api/alerts_history');
        const tbody=document.getElementById('alertsHistory').getElementsByTagName('tbody')[0];
        if(!d.length){tbody.innerHTML='<tr><td colspan="4" class="loading">No alerts yet</td></tr>';return;}
        tbody.innerHTML=d.map(a=>`<tr><td>${a.ts}</td><td><span class="badge ${a.severity=='critical'?'threat':''}">${a.severity}</span></td><td>${a.feed||'local'}</td><td>${a.msg}</td></tr>`).join('');
    }catch(e){console.error(e)}
}

async function update(){
try{
const range=document.getElementById('timeRange').value;
const [ov,bw,cv]=await Promise.all([
    fetchJson('/api/overview?range='+range),
    fetchJson('/api/bandwidth'),
    fetchJson('/api/conversations', {}, 2, 800)
]);
const conversations = Array.isArray(cv.conversations)?cv.conversations:[];

document.getElementById('totalTraffic').textContent=ov.totals.bytes_fmt;
document.getElementById('totalFlows').textContent=ov.totals.flows.toLocaleString();
document.getElementById('avgPacketSize').textContent=ov.totals.avg_packet_size+' B';

if(ov.alerts&&ov.alerts.length>0){
    document.getElementById('alertsContainer').innerHTML=ov.alerts.map(a=>`<div class="alert-box ${a.severity}">${a.msg}${ov.threat_feed_updated?` (feed ${a.feed||''}, updated ${ov.threat_feed_updated})`:''}</div>`).join('');
}else{
    document.getElementById('alertsContainer').innerHTML='';
}

updateNotifyButtons(ov.notify||{email:true,webhook:true});
updateFeedStatus(ov.threat_status);

const fmt=b=>b>=1024**3?(b/1024**3).toFixed(2)+' GB':b>=1024**2?(b/1024**2).toFixed(2)+' MB':b>=1024?(b/1024).toFixed(2)+' KB':b+' B';

function formatIPRow(i){
    const flag=i.flag?`<span class="flag">${i.flag}</span>`:'';
    const city=i.city?` <span class="region">${i.city}</span>`:'';
    const asn=i.asn?` <span class="region">ASN ${i.asn} ${i.asn_org||''}</span>`:'';
    const threat=i.threat?'<span class="badge threat">THREAT</span>':'';
    return `<tr onclick=\"showIPDetail('${i.key}')\"><td><strong class="ip-clickable">${i.key}</strong> ${flag} <span class="badge ${i.internal?'internal':'external'}">${i.region}</span>${city}${asn}${i.hostname?`<span class="hostname">${i.hostname}</span>`:''} ${threat}</td><td><span class="badge">${fmt(i.bytes)}</span></td></tr>`;
}

document.getElementById('topSources').getElementsByTagName('tbody')[0].innerHTML=ov.top_sources.slice(0,10).map(i=>formatIPRow(i)).join('');

document.getElementById('topDests').getElementsByTagName('tbody')[0].innerHTML=ov.top_destinations.slice(0,10).map(i=>formatIPRow(i)).join('');

document.getElementById('topPorts').getElementsByTagName('tbody')[0].innerHTML=ov.top_ports.slice(0,12).map(i=>`<tr><td><strong>${i.key}</strong></td><td>${i.service}</td><td><span class="badge ${i.suspicious?'suspicious':''}">${fmt(i.bytes)}</span></td></tr>`).join('');

document.getElementById('protocols').getElementsByTagName('tbody')[0].innerHTML=ov.protocols.slice(0,6).map(i=>`<tr><td><strong>${i.proto_name}</strong></td><td>${fmt(i.bytes)}</td><td>${i.flows.toLocaleString()}</td></tr>`).join('');

if(ov.top_countries){
    document.getElementById('topCountries').getElementsByTagName('tbody')[0].innerHTML=ov.top_countries.map(i=>`<tr><td><span class="flag">${i.flag}</span> ${i.name}</td><td><span class="badge">${fmt(i.bytes)}</span></td></tr>`).join('') || '<tr><td colspan="2">No external traffic</td></tr>';
}

if(ov.top_asns){
    document.getElementById('topASNs').getElementsByTagName('tbody')[0].innerHTML=ov.top_asns.map(i=>`<tr><td>${i.asn}</td><td>${i.as_org}</td><td><span class="badge">${fmt(i.bytes)}</span></td></tr>`).join('') || '<tr><td colspan="3">No external traffic</td></tr>';
}

document.getElementById('conversations').getElementsByTagName('tbody')[0].innerHTML=conversations.length?conversations.map(i=>`<tr><td onclick="showIPDetail('${i.src}')"><strong class="ip-clickable">${i.src}</strong><span class="region">${i.src_region}</span></td><td><span class="arrow">→</span></td><td onclick="showIPDetail('${i.dst}')"><strong class="ip-clickable">${i.dst}</strong><span class="region">${i.dst_region}</span></td><td><span class="badge">${i.bytes_fmt}</span></td></tr>`).join(''):'<tr><td colspan="4" class="loading">No data</td></tr>';

updateChart(bw);
document.getElementById('lastUpdate').textContent='Updated: '+new Date().toLocaleTimeString();
loadAlertsHistory();
}catch(e){console.error(e); document.getElementById('lastUpdate').textContent='Error: '+e;}
}

function updateChart(d){
const ctx=document.getElementById('bwChart').getContext('2d');
const colors=currentTheme=='green'?{line1:'#39ff14',line2:'#00ff41',bg1:'rgba(57,255,20,0.1)',bg2:'rgba(0,255,65,0.1)',text:'#00ff41',grid:'#00ff41'}:{line1:'#667eea',line2:'#764ba2',bg1:'rgba(102,126,234,0.1)',bg2:'rgba(118,75,162,0.1)',text:'#e0e0e0',grid:'#2a2a2a'};
if(chart){chart.data.labels=d.labels;chart.data.datasets[0].data=d.bandwidth;chart.data.datasets[1].data=d.flows;chart.update()}
else{chart=new Chart(ctx,{type:'line',data:{labels:d.labels,datasets:[{label:'Mbps',data:d.bandwidth,borderColor:colors.line1,backgroundColor:colors.bg1,borderWidth:2,tension:0.4,yAxisID:'y'},{label:'Flows/s',data:d.flows,borderColor:colors.line2,backgroundColor:colors.bg2,borderWidth:2,tension:0.4,yAxisID:'y1'}]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},plugins:{legend:{position:'top',labels:{color:colors.text}}},scales:{y:{type:'linear',display:true,position:'left',title:{display:true,text:'Mbps',color:colors.text},ticks:{color:colors.text},grid:{color:colors.grid}},y1:{type:'linear',display:true,position:'right',title:{display:true,text:'Flows/s',color:colors.text},ticks:{color:colors.text},grid:{drawOnChartArea:false}},x:{ticks:{color:colors.text},grid:{color:colors.grid}}}}})}
}

// init
window.addEventListener('load', ()=>{
    document.getElementById('refreshSelect').value=refreshMs;
    loadStoredUI();
    update();
    schedule();
    loadNotifyStatus();
});
</script>
</body></html>'''

if __name__=="__main__":
    print("NetFlow Analytics Pro (Enhanced v9 - sparklines, throttles, status)")
    app.run(host="0.0.0.0",port=8080,threaded=True)
