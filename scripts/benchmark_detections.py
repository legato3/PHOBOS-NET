
import time
import sys
import os
import random
import types
import importlib.util
from collections import defaultdict, deque
from unittest.mock import MagicMock

# Mock external dependencies
sys.modules['flask'] = MagicMock()
sys.modules['flask_login'] = MagicMock()
sys.modules['flask_compress'] = MagicMock()
sys.modules['flask_talisman'] = MagicMock()
sys.modules['gevent'] = MagicMock()
sys.modules['gevent.pywsgi'] = MagicMock()
sys.modules['dns'] = MagicMock()
sys.modules['dns.resolver'] = MagicMock()
sys.modules['dns.reversename'] = MagicMock()
sys.modules['maxminddb'] = MagicMock()
sys.modules['requests'] = MagicMock()
sys.modules['requests.adapters'] = MagicMock()
sys.modules['requests.exceptions'] = MagicMock()
sys.modules['psutil'] = MagicMock()

# Setup app package structure
app_pkg = types.ModuleType('app')
app_pkg.__path__ = []
sys.modules['app'] = app_pkg

sys.modules['app.core'] = types.ModuleType('app.core')
sys.modules['app.services'] = types.ModuleType('app.services')
sys.modules['app.services.shared'] = types.ModuleType('app.services.shared')
sys.modules['app.services.security'] = types.ModuleType('app.services.security')

# Mock internal dependencies
sys.modules['app.core.app_state'] = MagicMock()
sys.modules['app.services.shared.observability'] = MagicMock()
sys.modules['app.services.shared.helpers'] = MagicMock()
sys.modules['app.services.shared.geoip'] = MagicMock()
sys.modules['app.services.shared.config_helpers'] = MagicMock()
sys.modules['app.db.sqlite'] = MagicMock()

# Manually load app.config
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
config_path = os.path.join(repo_root, "app/config.py")
spec = importlib.util.spec_from_file_location("app.config", config_path)
config = importlib.util.module_from_spec(spec)
sys.modules["app.config"] = config
spec.loader.exec_module(config)

# Override config constants
config.PORTS = {}
config.SUSPICIOUS_PORTS = {22, 23, 3389, 445}
config.BRUTE_FORCE_PORTS = {22, 3389, 445}
config.PORT_SCAN_THRESHOLD = 5 # Low threshold for test
config.PORT_SCAN_WINDOW = 60
config.EXFIL_THRESHOLD_MB = 100
config.EXFIL_RATIO_THRESHOLD = 5
config.DNS_QUERY_THRESHOLD = 5 # Low threshold for test
config.BUSINESS_HOURS_START = 8
config.BUSINESS_HOURS_END = 18
config.OFF_HOURS_THRESHOLD_MB = 50
config.VIRUSTOTAL_API_KEY = None
config.ABUSEIPDB_API_KEY = None
config.MITRE_MAPPINGS = {}
config.WATCHLIST_PATH = "/tmp/watchlist"
config.THREATLIST_PATH = "/tmp/threatlist"
config.THREAT_FEEDS_PATH = "/tmp/feeds"
config.THREAT_FEED_URL_PATH = "/tmp/feed_url"
config.SECURITY_WEBHOOK_PATH = "/tmp/webhook"
config.WEBHOOK_PATH = "/tmp/webhook_legacy"

# Setup helpers mocks
from app.services.shared.helpers import is_internal, fmt_bytes
is_internal.side_effect = lambda ip: ip.startswith("192.168.") or ip.startswith("10.")
fmt_bytes.side_effect = lambda b: f"{b} B"

from app.services.shared.observability import instrument_service
instrument_service.side_effect = lambda name: lambda func: func

# Manually load app.services.security.threats
threats_path = os.path.join(repo_root, "app/services/security/threats.py")
threats_spec = importlib.util.spec_from_file_location("app.services.security.threats", threats_path)
threats = importlib.util.module_from_spec(threats_spec)
sys.modules["app.services.security.threats"] = threats
threats_spec.loader.exec_module(threats)

# Patch globals
threats._alert_history = deque(maxlen=1000)
threats._port_scan_tracker = {}
threats._anomaly_tracker = {}
threats.load_watchlist = MagicMock(return_value=set())
threats.load_threatlist = MagicMock(return_value=set())

def generate_attack_traffic():
    flows = []
    # Port scan from 1.2.3.4
    for p in range(20, 30):
        flows.append({
            "src_ip": "1.2.3.4",
            "dst_ip": "192.168.1.1",
            "src_port": "50000",
            "dst_port": str(p),
            "proto": "6",
            "bytes": 100,
            "flows": 1,
            "key": "1.2.3.4"
        })

    # DNS anomaly from 1.2.3.5
    for _ in range(10):
        flows.append({
            "src_ip": "1.2.3.5",
            "dst_ip": "8.8.8.8",
            "src_port": "50000",
            "dst_port": "53",
            "proto": "17",
            "bytes": 100,
            "flows": 1,
            "key": "1.2.3.5"
        })

    # Brute force on 22 from 1.2.3.6
    for _ in range(60):
        flows.append({
            "src_ip": "1.2.3.6",
            "dst_ip": "192.168.1.1",
            "src_port": "50000",
            "dst_port": "22",
            "proto": "6",
            "bytes": 100,
            "flows": 1,
            "key": "1.2.3.6"
        })

    return flows

def verify_functionality():
    print("Verifying functionality...")
    flow_data = generate_attack_traffic()
    alerts = threats.run_all_detections([], [], [], [], flow_data=flow_data)

    print(f"Generated {len(alerts)} alerts.")
    alert_types = [a['type'] for a in alerts]
    print(f"Alert types: {set(alert_types)}")

    assert "port_scan" in alert_types, "Port scan not detected"
    assert "dns_tunneling" in alert_types, "DNS tunneling not detected"
    assert "brute_force" in alert_types, "Brute force not detected"
    print("Verification passed!")

def generate_flow_data(count=2000):
    flows = []
    ips = [f"192.168.1.{i}" for i in range(1, 20)] + [f"10.0.0.{i}" for i in range(1, 20)] + [f"1.2.3.{i}" for i in range(1, 50)]
    ports = [80, 443, 22, 53, 3389, 8080] + list(range(1000, 2000))

    for _ in range(count):
        src = random.choice(ips)
        dst = random.choice(ips)
        port = random.choice(ports)
        flows.append({
            "src_ip": src,
            "dst_ip": dst,
            "src_port": str(random.randint(1024, 65535)),
            "dst_port": str(port),
            "proto": "6",
            "bytes": random.randint(64, 1000000),
            "flows": 1,
            "key": src, # Fallback
            "port": port # Fallback
        })
    return flows

def generate_summary_data(count=50):
    data = []
    ips = [f"1.2.3.{i}" for i in range(1, count+1)]
    for ip in ips:
        data.append({
            "key": ip,
            "bytes": random.randint(1000, 100000000)
        })
    return data

def benchmark():
    flow_data = generate_flow_data(10000)
    sources_data = generate_summary_data()
    destinations_data = generate_summary_data()
    protocols_data = [{"key": "6", "bytes": 1000}]

    print(f"Benchmarking with {len(flow_data)} flows...")

    # Warmup
    threats.run_all_detections([], sources_data, destinations_data, protocols_data, flow_data=flow_data[:100])

    start = time.time()
    iterations = 20
    for _ in range(iterations):
        threats.run_all_detections([], sources_data, destinations_data, protocols_data, flow_data=flow_data)

    duration = time.time() - start
    print(f"Time for {iterations} runs: {duration:.4f}s")
    print(f"Avg time per run: {duration/iterations:.4f}s")

if __name__ == "__main__":
    verify_functionality()
    benchmark()
