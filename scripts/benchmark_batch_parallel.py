import time
import json
import sys
import os

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app

def benchmark():
    app = create_app()
    client = app.test_client()

    # Payload: 5 requests to 'summary' with different params to bypass cache
    # We will instrument 'summary' to sleep for 1 second.
    # Parallel expected: ~1s (max of concurrent requests)
    # Sequential expected: ~5s (sum of requests)
    payload = {
        'requests': [
            {'endpoint': 'summary', 'params': {'range': '15m'}},
            {'endpoint': 'summary', 'params': {'range': '30m'}},
            {'endpoint': 'summary', 'params': {'range': '1h'}},
            {'endpoint': 'summary', 'params': {'range': '6h'}},
            {'endpoint': 'summary', 'params': {'range': '24h'}}
        ]
    }

    start_time = time.time()
    response = client.post('/api/stats/batch', json=payload)
    end_time = time.time()
    duration = end_time - start_time

    print(f"Status Code: {response.status_code}")
    print(f"Duration: {duration:.2f} seconds")

    if response.status_code != 200:
        print("Error response:", response.get_json())

    if duration < 2.0:
        print("SUCCESS: Execution time indicates PARALLEL processing.")
    elif duration > 4.0:
        print("FAILURE: Execution time indicates SEQUENTIAL processing.")
    else:
        print("WARNING: Execution time is ambiguous.")

if __name__ == "__main__":
    benchmark()
