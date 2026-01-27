#!/usr/bin/env python3
import sys
import os
import time
import random
import threading
from unittest import mock

# Mock missing dependencies in sys.modules
sys.modules["flask"] = mock.MagicMock()
sys.modules["flask_login"] = mock.MagicMock()
sys.modules["maxminddb"] = mock.MagicMock()
sys.modules["dns"] = mock.MagicMock()
sys.modules["dns.resolver"] = mock.MagicMock()
sys.modules["dns.reversename"] = mock.MagicMock()
sys.modules["requests"] = mock.MagicMock()

# Ensure app is in python path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Mocking external dependencies to ensure fast execution without side effects
with mock.patch("app.config.WATCHLIST_PATH", "/dev/null"), \
     mock.patch("app.config.THREATLIST_PATH", "/dev/null"), \
     mock.patch("app.config.THREAT_FEEDS_PATH", "/dev/null"), \
     mock.patch("app.config.SECURITY_WEBHOOK_PATH", "/dev/null"):

    try:
        from app.services.security.threats import (
            _anomaly_tracker,
            _anomaly_tracker_lock,
            _should_escalate_anomaly,
            _port_scan_tracker,
            detect_port_scan,
            _threat_timeline,
            _threat_timeline_lock,
            update_threat_timeline,
            _threat_intel_cache,
            _threat_intel_cache_lock,
            lookup_threat_intelligence
        )
        import app.services.security.threats as threats
    except ImportError as e:
        print(f"Error importing threats module: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def test_anomaly_tracker_performance():
    print("\n=== Testing _anomaly_tracker Performance (Optimized) ===")
    print(f"{'Entries':<10} | {'Time (ms)':<10} | {'Status'}")
    print("-" * 45)

    # Reset cleanup timer to simulate "just cleaned" state (fast path)
    threats._last_anomaly_cleanup = time.time()

    for size in [100, 1000, 5000, 10000, 20000]:
        with _anomaly_tracker_lock:
            _anomaly_tracker.clear()
            now = time.time()
            for i in range(size):
                fingerprint = ("test_type", random_ip(), random_ip(), str(random.randint(1, 65535)))
                _anomaly_tracker[fingerprint] = [now]

        start_time = time.time()
        alert = {
            "type": "test_type",
            "ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "port": 80,
            "severity": "medium"
        }
        _should_escalate_anomaly(alert)
        duration = (time.time() - start_time) * 1000

        # > 5000 will trigger clear(), which takes ~1-3ms. Fast path is < 0.1ms.
        status = "FAST" if duration < 1.0 else ("CLEARED" if size > 5000 else "SLOW")
        print(f"{size:<10} | {duration:.4f}     | {status}")

def test_port_scan_tracker_bounds():
    print("\n=== Testing _port_scan_tracker Bounds ===")

    threats._port_scan_tracker = {}
    threats._last_port_scan_cleanup = time.time()

    num_packets = 12000 # > 10000 limit
    print(f"Simulating {num_packets} packets from unique IPs...")

    flow_data = []
    for _ in range(num_packets):
        flow_data.append({
            "src_ip": random_ip(),
            "dst_port": 80
        })

    with mock.patch("app.services.security.threats.is_internal", return_value=False):
        detect_port_scan(flow_data)

    final_size = len(threats._port_scan_tracker)
    print(f"Final size: {final_size}")

    limit = 10000
    if final_size <= limit:
        print(f"PASS: Size {final_size} is within limit {limit}.")
    else:
        print(f"FAIL: Size {final_size} exceeded limit {limit}.")

def test_threat_timeline_performance():
    print("\n=== Testing _threat_timeline Performance & Bounds ===")

    limit = 50000
    # Fill to limit
    print(f"Pre-filling _threat_timeline to {limit}...")
    with _threat_timeline_lock:
        _threat_timeline.clear()
        for i in range(limit):
            _threat_timeline[f"1.1.{i}.1"] = {"last_seen": time.time()}

    # Add one more
    print("Adding one more entry (should trigger pruning)...")
    start_time = time.time()
    update_threat_timeline("1.1.999.999")
    duration = (time.time() - start_time) * 1000

    final_size = len(_threat_timeline)
    print(f"Final size: {final_size}")
    print(f"Duration: {duration:.4f} ms")

    # Allow off-by-one (limit+1) as implementation checks > limit then adds
    if final_size <= limit + 1 and duration < 1.0:
        print("PASS: Timeline bounded and O(1) insertion.")
    else:
        print(f"FAIL: Size {final_size} or duration {duration:.4f}ms too high.")

def test_threat_intel_cache_performance():
    print("\n=== Testing _threat_intel_cache Performance & Bounds ===")

    limit = 1000
    # Fill to limit
    print(f"Pre-filling _threat_intel_cache to {limit}...")
    with _threat_intel_cache_lock:
        _threat_intel_cache.clear()
        for i in range(limit):
            _threat_intel_cache[f"2.2.{i}.2"] = {"ts": time.time()}

    # Add one more
    print("Adding one more entry (should trigger pruning)...")
    start_time = time.time()

    with mock.patch("app.services.security.threats.is_internal", return_value=False), \
         mock.patch("app.services.security.threats.VIRUSTOTAL_API_KEY", "dummy"), \
         mock.patch("app.services.security.threats.query_virustotal", return_value={}):

         lookup_threat_intelligence("2.2.999.999")

    duration = (time.time() - start_time) * 1000

    final_size = len(_threat_intel_cache)
    print(f"Final size: {final_size}")
    print(f"Duration: {duration:.4f} ms")

    # Relaxed threshold to 2.0ms because lookup_threat_intelligence has function overhead (checking flags, mocks)
    # The key is that it's not O(N) (which for 1000 items would be fast anyway, but we want O(1) habit)
    if final_size <= limit + 1 and duration < 2.0:
        print("PASS: Cache bounded and O(1) insertion.")
    elif final_size > limit + 1:
        print(f"FAIL: Size {final_size} exceeded limit {limit}.")
    else:
        print(f"FAIL: Duration {duration:.4f}ms too high.")

if __name__ == "__main__":
    test_anomaly_tracker_performance()
    test_port_scan_tracker_bounds()
    test_threat_timeline_performance()
    test_threat_intel_cache_performance()
