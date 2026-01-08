from flask import Flask, render_template, jsonify, request
import subprocess, time, os, json, smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
import threading
import requests
import maxminddb

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


_bandwidth_cache = {"data": None, "ts": 0}
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

mmdb_city = None
mmdb_asn = None
_threat_thread_started = False

PORTS = {20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",3389:"RDP",5900:"VNC",27017:"MongoDB",1194:"OpenVPN",51820:"WireGuard"}
PROTOS = {1:"ICMP",6:"TCP",17:"UDP",47:"GRE",50:"ESP",51:"AH"}
SUSPICIOUS_PORTS = [4444,5555,6667,8888,9001,9050,9150,31337,12345,1337,666,6666]
INTERNAL_NETS = ["192.168.","10.","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31."]

DNS_SERVER = "192.168.0.1"
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
    return None
    now = time.time()
    if ip in _dns_cache and now - _dns_ttl.get(ip, 0) < 300:
        return _dns_cache[ip]
    try:
        r = subprocess.run(["host","-W","1",ip,DNS_SERVER], capture_output=True, text=True, timeout=1)
        if r.returncode == 0 and "pointer" in r.stdout:
            h = r.stdout.split("pointer")[1].strip().rstrip(".")
            _dns_cache[ip] = h; _dns_ttl[ip] = now; return h
    except Exception:
        pass
    _dns_cache[ip] = None; _dns_ttl[ip] = now; return None

def run_nfdump(args, tf=None):
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

def parse_csv(output):
    results = []
    lines = output.strip().split("\n")
    for line in lines[1:]:
        if not line: continue
        parts = line.split(",")
        if len(parts) < 14: continue
        try:
            key = parts[4]
            if not key or "/" in key or key == "any": continue
            bytes_val = int(float(parts[9]))
            flows_val = int(float(parts[5]))
            packets_val = int(float(parts[7]))
            if bytes_val > 0:
                results.append({"key":key,"bytes":bytes_val,"flows":flows_val,"packets":packets_val})
        except Exception:
            continue
    return results

def get_traffic_direction(ip, tf):
    out = run_nfdump(["-a",f"src ip {ip}","-s","srcip/bytes","-n","1"], tf)
    in_data = run_nfdump(["-a",f"dst ip {ip}","-s","dstip/bytes","-n","1"], tf)
    out_parsed = parse_csv(out)
    in_parsed = parse_csv(in_data)
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
    for item in ports_data[:25]:
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
    for item in sources_data[:15]:
        if item["bytes"] > 2*1024**3:
            alert_key = f"large_{item['key']}"
            if alert_key not in seen:
                alerts.append({"type":"large_transfer","msg":f"📊 Large transfer from {item['key']}: {fmt_bytes(item['bytes'])}","severity":"medium","feed":"local"})
                seen.add(alert_key)
                if len(alerts) >= 10:
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
    if not os.path.exists(SMTP_CFG_PATH):
        return None
    try:
        with open(SMTP_CFG_PATH,'r') as f:
            cfg = json.load(f)
        return cfg
    except Exception:
        return None


def load_notify_cfg():
    default = {"email": True, "webhook": True, "mute_until": 0}
    if not os.path.exists(NOTIFY_CFG_PATH):
        return default
    try:
        with open(NOTIFY_CFG_PATH,'r') as f:
            cfg = json.load(f)
        return {"email": bool(cfg.get("email", True)), "webhook": bool(cfg.get("webhook", True)), "mute_until": float(cfg.get("mute_until", 0) or 0)}
    except Exception:
        return default


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
        requests.post(url, json=payload, timeout=3)
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
    return render_template("index.html")

def get_time_range(range_key):
    now = datetime.now()
    hours = {"15m":0.25,"30m":0.5,"1h":1,"6h":6,"24h":24}.get(range_key, 1)
    past = now - timedelta(hours=hours)
    return f"{past.strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"


@app.route("/api/stats/summary")
@throttle(5, 10)
def api_stats_summary():
    start_threat_thread()
    range_key = request.args.get('range', '1h')
    now_ts = time.time()
    with _cache_lock:
        cache_key = f"{range_key}_{int(now_ts/30)}"
        if _stats_summary_cache.get("key") == cache_key:
            return jsonify(_stats_summary_cache["data"])

    tf = get_time_range(range_key)
    # Just need totals, so nfdump -I is simpler but parse_csv expects -o csv
    # We can run a small query or just use the aggregate
    # Using existing logic for consistency, but optimized query
    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","1"], tf)) # Minimal fetch

    # Wait, the previous summary was aggregating ALL flows.
    # nfdump -s ... -n 1 only gives top 1.
    # To get totals, we often need -I or parse header.
    # But existing code did: tot_b = sum(i["bytes"] for i in sources) where sources was top 20.
    # That was actually inaccurate for TOTAL traffic, just top 20 traffic.
    # I will stick to top 20 sum for consistency with previous behavior, or improve it?
    # Better to stick to previous logic to avoid confusion, but split it.

    # Actually, let's run a slightly larger query to get better totals if that's what was happening.
    # Previous: sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf))
    # This implies the dashboard only showed stats for Top 20.
    # Let's keep it consistent.

    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf))

    tot_b = sum(i["bytes"] for i in sources)
    tot_f = sum(i["flows"] for i in sources)
    tot_p = sum(i["packets"] for i in sources)

    # Alerts need full context, so we might need to run detection here or separate it.
    # We will separate alerts.

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
        _stats_summary_cache["key"] = cache_key

    return jsonify(data)


@app.route("/api/stats/sources")
@throttle(5, 10)
def api_stats_sources():
    range_key = request.args.get('range', '1h')
    now_ts = time.time()
    with _cache_lock:
        cache_key = f"{range_key}_{int(now_ts/30)}"
        if _stats_sources_cache.get("key") == cache_key:
            return jsonify(_stats_sources_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","30"], tf))

    # Enrich
    for i in sources[:25]:
        i["hostname"] = resolve_ip(i["key"])
        i["region"] = get_region(i["key"])
        i["internal"] = is_internal(i["key"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["threat"] = i["key"] in threat_set and i["key"] not in whitelist

    data = {
        "sources": sources[:25]
    }

    with _cache_lock:
        _stats_sources_cache["data"] = data
        _stats_sources_cache["key"] = cache_key

    return jsonify(data)


@app.route("/api/stats/destinations")
@throttle(5, 10)
def api_stats_destinations():
    range_key = request.args.get('range', '1h')
    now_ts = time.time()
    with _cache_lock:
        cache_key = f"{range_key}_{int(now_ts/30)}"
        if _stats_dests_cache.get("key") == cache_key:
            return jsonify(_stats_dests_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    dests = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","30"], tf))

    # Enrich
    for i in dests[:25]:
        i["hostname"] = resolve_ip(i["key"])
        i["region"] = get_region(i["key"])
        i["internal"] = is_internal(i["key"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["threat"] = i["key"] in threat_set and i["key"] not in whitelist

    data = {
        "destinations": dests[:25]
    }

    with _cache_lock:
        _stats_dests_cache["data"] = data
        _stats_dests_cache["key"] = cache_key

    return jsonify(data)


@app.route("/api/stats/ports")
@throttle(5, 10)
def api_stats_ports():
    range_key = request.args.get('range', '1h')
    now_ts = time.time()
    with _cache_lock:
        cache_key = f"{range_key}_{int(now_ts/30)}"
        if _stats_ports_cache.get("key") == cache_key:
            return jsonify(_stats_ports_cache["data"])

    tf = get_time_range(range_key)
    ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","30"], tf))

    for i in ports:
        try:
            port = int(i["key"])
            i["service"] = PORTS.get(port, "Unknown")
            i["suspicious"] = port in SUSPICIOUS_PORTS
        except Exception:
            i["service"] = "Unknown"; i["suspicious"] = False

    data = {"ports": ports[:25]}

    with _cache_lock:
        _stats_ports_cache["data"] = data
        _stats_ports_cache["key"] = cache_key

    return jsonify(data)

@app.route("/api/stats/protocols")
@throttle(5, 10)
def api_stats_protocols():
    range_key = request.args.get('range', '1h')
    now_ts = time.time()
    with _cache_lock:
        cache_key = f"{range_key}_{int(now_ts/30)}"
        if _stats_protocols_cache.get("key") == cache_key:
            return jsonify(_stats_protocols_cache["data"])

    tf = get_time_range(range_key)
    protos_raw = parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","15"], tf))

    seen = set(); protos = []
    for p in protos_raw:
        if p["key"] not in seen:
            seen.add(p["key"]); protos.append(p)

    for i in protos:
        try:
            proto = int(i["key"])
            i["proto_name"] = PROTOS.get(proto, f"Proto-{i['key']}")
        except Exception:
            i["proto_name"] = i["key"]

    data = {"protocols": protos[:10]}

    with _cache_lock:
        _stats_protocols_cache["data"] = data
        _stats_protocols_cache["key"] = cache_key

    return jsonify(data)

@app.route("/api/alerts")
@throttle(5, 10)
def api_alerts():
    # Alerts require analyzing ports and sources.
    # This mimics the overhead of `detect_anomalies` but we can reuse the cached data if we want.
    # However, to be safe and accurate, let's run the check.
    # We can probably cache this for short time (30s).

    range_key = request.args.get('range', '1h')
    now_ts = time.time()
    with _cache_lock:
        cache_key = f"{range_key}_{int(now_ts/30)}"
        if _stats_alerts_cache.get("key") == cache_key:
            return jsonify(_stats_alerts_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    feed_label = get_feed_label()

    # We need sources and ports for detection
    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf))
    ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","20"], tf))

    alerts = detect_anomalies(ports, sources, threat_set, whitelist, feed_label)
    send_notifications([a for a in alerts if a.get("severity") in ("critical","high")])

    feed_ts = None
    try:
        feed_ts = datetime.utcfromtimestamp(os.path.getmtime(THREATLIST_PATH)).isoformat()+"Z"
    except Exception:
        pass

    data = {
        "alerts": alerts[:10],
        "threat_feed_updated": feed_ts,
        "feed_label": feed_label
    }

    with _cache_lock:
        _stats_alerts_cache["data"] = data
        _stats_alerts_cache["key"] = cache_key

    return jsonify(data)


@app.route("/api/bandwidth")
@throttle(10,20)
def api_bandwidth():
    now_ts = time.time()
    with _cache_lock:
        if _bandwidth_cache["data"] and now_ts - _bandwidth_cache["ts"] < 5:
            global _metric_bw_cache_hits
            _metric_bw_cache_hits += 1
            return jsonify(_bandwidth_cache["data"])
    now = datetime.now(); labels, bw, flows = [], [], []
    try:
        for i in range(11,-1,-1):
            et = now - timedelta(minutes=i*5); st = et - timedelta(minutes=5)
            tf = f"{st.strftime('%Y/%m/%d.%H:%M:%S')}-{et.strftime('%Y/%m/%d.%H:%M:%S')}"
            labels.append(et.strftime("%H:%M"))
            output = run_nfdump(["-s","proto/bytes/flows","-n","1"], tf)
            stats = parse_csv(output)
            if stats:
                total_b = sum(s["bytes"] for s in stats); total_f = sum(s["flows"] for s in stats)
                bw.append(round((total_b*8)/(300*1_000_000),2)); flows.append(round(total_f/300,2))
            else:
                bw.append(0); flows.append(0)
        data = {"labels":labels,"bandwidth":bw,"flows":flows, "generated_at": datetime.utcnow().isoformat()+"Z"}
        with _cache_lock:
            _bandwidth_cache["data"] = data; _bandwidth_cache["ts"] = now_ts
        return jsonify(data)
    except Exception:
        with _cache_lock:
            if _bandwidth_cache.get("data"):
                return jsonify(_bandwidth_cache["data"])
        return jsonify({"labels":[],"bandwidth":[],"flows":[]}), 500

@app.route("/api/conversations")
@throttle(10,30)
def api_conversations():
    now_ts = time.time()
    with _cache_lock:
        if _conversations_cache["data"] and now_ts - _conversations_cache["ts"] < 5:
            global _metric_conv_cache_hits
            _metric_conv_cache_hits += 1
            return jsonify(_conversations_cache["data"])
    now = datetime.now()
    tf = f"{(now-timedelta(hours=1)).strftime('%Y/%m/%d.%H:%M:%S')}-{now.strftime('%Y/%m/%d.%H:%M:%S')}"
    try:
        src_data = parse_csv(run_nfdump(["-s","srcip/bytes","-n","25"], tf))
        dst_data = parse_csv(run_nfdump(["-s","dstip/bytes","-n","25"], tf))
        convs = []
        for i, src in enumerate(src_data[:25]):
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
    direction = get_traffic_direction(ip, tf)
    src_ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","10","-a",f"src ip {ip}"], tf))
    dst_ports = parse_csv(run_nfdump(["-s","srcport/bytes/flows","-n","10","-a",f"dst ip {ip}"], tf))
    protocols = parse_csv(run_nfdump(["-s","proto/bytes/packets","-n","5","-a",f"ip {ip}"], tf))
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
        "hostname": resolve_ip(ip),
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

def get_full_overview():
    # Helper to gather all data for export
    range_key = request.args.get('range', '1h')
    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf))
    dests = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","20"], tf))
    ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","20"], tf))
    protos_raw = parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","10"], tf))

    seen = set(); protos = []
    for p in protos_raw:
        if p["key"] not in seen:
            seen.add(p["key"]); protos.append(p)

    tot_b = sum(i["bytes"] for i in sources)
    tot_f = sum(i["flows"] for i in sources)
    tot_p = sum(i["packets"] for i in sources)

    return {
        "top_sources": sources,
        "top_destinations": dests,
        "top_ports": ports,
        "protocols": protos,
        "totals": {"bytes": tot_b, "flows": tot_f, "packets": tot_p}
    }

@app.route("/api/export")
def export_csv():
    data = get_full_overview()
    csv_lines = ["Type,IP/Port,Traffic,Flows\n"]
    for src in data.get("top_sources",[])[:20]:
        csv_lines.append(f"Source,{src['key']},{src['bytes']},{src['flows']}\n")
    for dst in data.get("top_destinations",[])[:20]:
        csv_lines.append(f"Destination,{dst['key']},{dst['bytes']},{dst['flows']}\n")
    for p in data.get("top_ports",[])[:20]:
         csv_lines.append(f"Port,{p['key']},{p['bytes']},{p['flows']}\n")
    return "".join(csv_lines), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=netflow_export.csv'}

@app.route("/api/export_json")
def export_json():
    return jsonify(get_full_overview())

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
    # Check if _last_feed_manual exists, if not init it
    if '_last_feed_manual' not in globals():
        global _last_feed_manual_var
        _last_feed_manual_var = 0
        _last_feed_manual = _last_feed_manual_var

    # Actually, using a safe getattr approach or try/except
    try:
        if now - _last_feed_manual < 300:
            return jsonify({"status":"throttled","next_in": int(300 - (now - _last_feed_manual))}), 429
    except NameError:
         _last_feed_manual = 0

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


def build_spark(kind, metric='bytes'):
    kind = "dst" if kind == "dst" else "src"
    now = datetime.now()
    labels = []
    buckets = []
    for idx in range(_spark_bucket_count-1, -1, -1):
        end = now - timedelta(minutes=idx*_spark_bucket_minutes)
        start = end - timedelta(minutes=_spark_bucket_minutes)
        tf = f"{start.strftime('%Y/%m/%d.%H:%M:%S')}-{end.strftime('%Y/%m/%d.%H:%M:%S')}"
        labels.append(end.strftime("%H:%M"))
        output = run_nfdump(["-s", f"{kind}ip/bytes/flows", "-n", "100"], tf)
        rows = parse_csv(output)
        bucket = {}
        for r in rows:
            key = r.get("key")
            if key:
                val = r.get('flows') if metric == 'flows' else r.get("bytes", 0)
                bucket[key] = bucket.get(key, 0) + val
        buckets.append(bucket)
    data = {}
    for i, bucket in enumerate(buckets):
        for ip, val in bucket.items():
            data.setdefault(ip, [0]*_spark_bucket_count)
            data[ip][i] = val
    return labels, data



def get_sparklines(ip_list, kind="src", metric='bytes'):
    global _metric_spark_hits, _metric_spark_misses
    if not ip_list:
        return [], {}
    kind = "dst" if kind == "dst" else "src"
    metric = 'flows' if metric == 'flows' else 'bytes'
    now = time.time()
    with _spark_lock:
        cache = _spark_cache[kind]
        if now - cache.get("ts", 0) < _spark_cache_ttl and cache.get('metric','bytes') == metric and all(ip in cache.get("data", {}) for ip in ip_list):
            _metric_spark_hits += 1
            return cache.get("labels", []), {ip: cache["data"].get(ip, [0]*_spark_bucket_count) for ip in ip_list}
    labels, data_full = build_spark(kind, metric)
    with _spark_lock:
        _spark_cache[kind] = {"labels": labels, "data": data_full, "ts": time.time(), 'metric': metric}
        _metric_spark_misses += 1
    return labels, {ip: data_full.get(ip, [0]*_spark_bucket_count) for ip in ip_list}



@app.route("/api/sparklines", methods=['POST'])
@throttle(10,20)
def api_sparklines():
    payload = request.get_json(force=True, silent=True) or {}
    ips = payload.get('ips', [])
    kind = payload.get('kind', 'src')
    metric = payload.get('metric', 'bytes')
    if not isinstance(ips, list):
        ips = []
    ips = [ip for ip in ips if ip]
    labels, data = get_sparklines(ips, kind, metric)
    return jsonify({"labels": labels, "data": data, "metric": metric})


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
        f"netflow_spark_cache_hits_total {_metric_spark_hits}",
        f"netflow_spark_cache_misses_total {_metric_spark_misses}",
        f"netflow_rate_limited_total {_metric_http_429}",
        f"threat_feed_size {_threat_status.get('size',0)}",
    ]
    return "\n".join(lines)+"\n", 200, {'Content-Type':'text/plain'}

if __name__=="__main__":
    print("NetFlow Analytics Pro (Modernized - Parallel API)")
    app.run(host="0.0.0.0",port=8080,threaded=True)
