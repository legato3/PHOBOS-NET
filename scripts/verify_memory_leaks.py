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
            detect_port_scan
        )
        import app.services.security.threats as threats
    except ImportError as e:
        print(f"Error importing threats module: {e}")
        # Print detailed traceback
        import traceback
        traceback.print_exc()
        sys.exit(1)

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def measure_escalation_time(num_entries):
    # Clear tracker
    with _anomaly_tracker_lock:
        _anomaly_tracker.clear()

    # Pre-populate with num_entries
    now = time.time()
    with _anomaly_tracker_lock:
        for i in range(num_entries):
            # Create unique fingerprint keys
            fingerprint = ("test_type", random_ip(), random_ip(), str(random.randint(1, 65535)))
            _anomaly_tracker[fingerprint] = [now]

    # Measure time for a SINGLE new check
    start_time = time.time()

    alert = {
        "type": "test_type",
        "ip": "192.168.1.100", # Fixed source
        "dest_ip": "10.0.0.1",
        "port": 80,
        "severity": "medium"
    }

    # We call _should_escalate_anomaly which performs the O(N) cleanup
    _should_escalate_anomaly(alert)

    end_time = time.time()
    return (end_time - start_time) * 1000 # ms

def test_anomaly_tracker_performance():
    print("\n=== Testing _anomaly_tracker Performance (O(N) cleanup) ===")
    print(f"{'Entries':<10} | {'Time (ms)':<10}")
    print("-" * 25)

    for size in [100, 1000, 5000, 10000, 20000]:
        duration = measure_escalation_time(size)
        print(f"{size:<10} | {duration:.4f}")

def test_port_scan_tracker_growth():
    print("\n=== Testing _port_scan_tracker Unbounded Growth ===")

    # Reset
    threats._port_scan_tracker = {}
    threats._last_port_scan_cleanup = time.time() # Ensure cleanup doesn't trigger immediately

    initial_size = len(threats._port_scan_tracker)
    print(f"Initial size: {initial_size}")

    # Simulate flood of unique IPs
    num_packets = 10000
    print(f"Simulating {num_packets} packets from unique IPs...")

    flow_data = []
    for _ in range(num_packets):
        flow_data.append({
            "src_ip": random_ip(),
            "dst_port": 80
        })

    # Mock is_internal to always return False
    with mock.patch("app.services.security.threats.is_internal", return_value=False):
        detect_port_scan(flow_data)

    final_size = len(threats._port_scan_tracker)
    print(f"Final size: {final_size}")

    if final_size >= num_packets * 0.9:
        print("CONFIRMED: _port_scan_tracker grew linearly with unique source IPs.")
    else:
        print(f"Result inconclusive: size {final_size} vs expected ~{num_packets}")

if __name__ == "__main__":
    test_anomaly_tracker_performance()
    test_port_scan_tracker_growth()
