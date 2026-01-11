
import time
import os
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys

# Set env to use a temp db
os.environ['TRENDS_DB_PATH'] = 'perf_test_trends.sqlite'
os.environ['FLASK_PORT'] = '8081'
os.environ['FLASK_DEBUG'] = 'true'

def start_server():
    # Start the server in background, showing output
    cmd = [sys.executable, 'netflow-dashboard.py']
    env = os.environ.copy()
    p = subprocess.Popen(cmd, env=env) # Let stdout/stderr go to console
    return p

def test_bandwidth_endpoint():
    print("Waiting for server to start...")
    time.sleep(5) # Give it time to start

    start_time = time.time()
    # Request 24h range (288 buckets)
    # This will trigger bucket filling if DB is empty
    print("Sending request...")
    try:
        r = requests.get('http://localhost:8081/api/bandwidth?range=24h', timeout=60) # 60s timeout
        print(f"Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            print(f"Got {len(data.get('bandwidth', []))} data points")
        else:
            print(f"Error: {r.text}")
    except Exception as e:
        print(f"Request failed: {e}")

    duration = time.time() - start_time
    print(f"Duration: {duration:.2f} seconds")

if __name__ == "__main__":
    if os.path.exists('perf_test_trends.sqlite'):
        os.remove('perf_test_trends.sqlite')

    p = start_server()
    try:
        test_bandwidth_endpoint()
    finally:
        print("Stopping server...")
        p.terminate()
        p.wait()
        if os.path.exists('perf_test_trends.sqlite'):
            os.remove('perf_test_trends.sqlite')
