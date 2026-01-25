import sys
import time
import os
from unittest.mock import MagicMock, patch

# Configure Mocks to isolate the test from the Flask application structure
# This prevents 'app.create_app()' from running on import.

mock_app_core = MagicMock()
sys.modules['app.core'] = mock_app_core
mock_app_state = MagicMock()
sys.modules['app.core.app_state'] = mock_app_state

mock_app_api = MagicMock()
sys.modules['app.api'] = mock_app_api
mock_routes = MagicMock()
sys.modules['app.api.routes'] = mock_routes
sys.modules['app.api.routes.firewall_decisions'] = MagicMock()

sys.modules['app.services.netflow'] = MagicMock()
sys.modules['app.services.netflow.netflow'] = MagicMock()

mock_observability = MagicMock()
def mock_instrument_service(*args, **kwargs):
    def decorator(func):
        return func
    return decorator
mock_observability.instrument_service = mock_instrument_service
sys.modules['app.services.shared.observability'] = mock_observability

mock_helpers = MagicMock()
sys.modules['app.services.shared.helpers'] = mock_helpers

mock_geoip = MagicMock()
sys.modules['app.services.shared.geoip'] = mock_geoip

mock_config_helpers = MagicMock()
sys.modules['app.services.shared.config_helpers'] = mock_config_helpers

# Mock Configuration
mock_config = MagicMock()
mock_config.THREAT_FEEDS_PATH = "/tmp/threat-feeds.txt"
mock_config.THREAT_FEED_URL_PATH = "/tmp/threat-feed-url.txt"
mock_config.WATCHLIST_PATH = "/tmp/watchlist.txt"
mock_config.THREATLIST_PATH = "/tmp/threats.txt"
mock_config.MITRE_MAPPINGS = {}
mock_config.SECURITY_WEBHOOK_PATH = "/tmp/webhook.json"
mock_config.WEBHOOK_PATH = "/tmp/webhook.txt"
mock_config.PORTS = {}
mock_config.SUSPICIOUS_PORTS = []
mock_config.BRUTE_FORCE_PORTS = []
mock_config.PORT_SCAN_THRESHOLD = 10
mock_config.PORT_SCAN_WINDOW = 60
mock_config.EXFIL_THRESHOLD_MB = 100
mock_config.EXFIL_RATIO_THRESHOLD = 10
mock_config.DNS_QUERY_THRESHOLD = 1000
mock_config.BUSINESS_HOURS_START = 9
mock_config.BUSINESS_HOURS_END = 17
mock_config.OFF_HOURS_THRESHOLD_MB = 50
mock_config.VIRUSTOTAL_API_KEY = None
mock_config.ABUSEIPDB_API_KEY = None
mock_config.MAX_FEED_WORKERS = 10

sys.modules['app.config'] = mock_config

# Import module under test
from app.services.security.threats import fetch_threat_feed

# Test setup
FEED_COUNT = 5
DELAY = 0.5 # Faster test

def benchmark():
    print(f"Benchmarking fetch_threat_feed with {FEED_COUNT} feeds, {DELAY}s delay each...")

    class MockResponse:
        def __init__(self, url):
            self.url = url
            self.status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_lines(self, decode_unicode=True):
            yield f"1.2.3.4"

    class MockSession:
        def mount(self, prefix, adapter):
            pass

        def get(self, url, **kwargs):
            time.sleep(DELAY)
            return MockResponse(url)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    with patch('requests.Session', side_effect=MockSession):
        feed_content = "\n".join([f"http://example.com/feed{i}|CAT|feed{i}" for i in range(FEED_COUNT)])

        def mock_open_func(file, mode='r'):
            if file == mock_config.THREAT_FEEDS_PATH:
                from io import StringIO
                return StringIO(feed_content)
            if 'tmp' in str(file):
                 return MagicMock()
            return MagicMock()

        def mock_exists(path):
            if path == mock_config.THREAT_FEEDS_PATH:
                return True
            return False

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('builtins.open', side_effect=mock_open_func), \
             patch('os.replace'):

            start = time.time()
            fetch_threat_feed()
            duration = time.time() - start

            print(f"Total duration: {duration:.2f}s")

            # Allow overhead: parallel execution should be close to max(latency) = DELAY
            # Sequential would be FEED_COUNT * DELAY

            limit = DELAY * 1.5 # Allow 50% overhead
            sequential_time = FEED_COUNT * DELAY

            if duration < limit:
                print("PASS: Parallelism detected.")
                sys.exit(0)
            elif duration >= (sequential_time * 0.9):
                print(f"FAIL: Sequential execution detected (Duration: {duration:.2f}s, Expected Seq: {sequential_time}s).")
                sys.exit(1)
            else:
                print(f"WARN: Inconclusive duration ({duration:.2f}s). Expected < {limit}s.")
                # If it's not strictly parallel but faster than sequential, it might be partial parallel or overhead
                sys.exit(1)

if __name__ == "__main__":
    benchmark()
