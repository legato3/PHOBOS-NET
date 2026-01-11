
import time
import os
import requests
import threading
from concurrent.futures import ThreadPoolExecutor

# Set env to use a temp db
os.environ['TRENDS_DB_PATH'] = 'perf_test_trends.sqlite'
os.environ['FLASK_PORT'] = '8081'

# We need to start the app in a background thread or process
# But simplest is to import the app and call the function directly if possible,
# or start it as a subprocess.

import subprocess
import sys

def start_server():
    # Start the server in background
    cmd = [sys.executable, 'netflow-dashboard.py']
    env = os.environ.copy()
    env['FLASK_DEBUG'] = 'false'
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p

def test_bandwidth_endpoint():
    print("Waiting for server to start...")
    time.sleep(5) # Give it time to start

    start_time = time.time()
    # Request 24h range (288 buckets)
    # This will trigger bucket filling if DB is empty
    try:
        r = requests.get('http://localhost:8081/api/bandwidth?range=24h')
        print(f"Status: {r.status_code}")
        data = r.json()
        print(f"Got {len(data.get('bandwidth', []))} data points")
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
        p.terminate()
        p.wait()
        if os.path.exists('perf_test_trends.sqlite'):
            os.remove('perf_test_trends.sqlite')
