
import time
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append(os.getcwd())

from app import create_app
import app.core.app_state as state

def benchmark():
    app = create_app()
    client = app.test_client()

    # Mock state to simulate "Real Mode" (has nfdump)
    state._has_nfdump = True

    print("Starting benchmark...")

    # Mock the rollup function to simulate work (0.05s per bucket)
    # 288 buckets * 0.05s = 14.4s serial work
    # With 8 workers: ~1.8s
    # If non-blocking: ~0s
    mock_rollup = MagicMock(side_effect=lambda x: time.sleep(0.05))

    start_time = time.time()

    # We want to verify that tasks are SUBMITTED to the executor.
    # We patch the executor used in traffic.py
    with patch('app.api.routes.traffic._rollup_executor') as mock_executor:
        with patch('app.api.routes.traffic._ensure_rollup_for_bucket', mock_rollup):
            # We also need to mock sqlite to return empty rows so all buckets are "missing"
            with patch('app.api.routes.traffic.sqlite3') as mock_sqlite:
                # Setup mock DB to return empty rows for "SELECT bucket_end..."
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_sqlite.connect.return_value = mock_conn
                mock_conn.execute.return_value = mock_cursor
                mock_cursor.fetchall.return_value = [] # No rows = all missing

                # Call the endpoint
                print("Requesting /api/bandwidth?range=24h")
                response = client.get('/api/bandwidth?range=24h')

                print(f"Response status: {response.status_code}")

                # Verify calls
                # 24h = 288 buckets. We expect 288 submissions.
                submit_count = mock_executor.submit.call_count
                print(f"Submissions to executor: {submit_count}")

    end_time = time.time()
    duration = end_time - start_time
    print(f"Duration: {duration:.4f} seconds")

    if duration < 1.0:
        print("SUCCESS: Endpoint is non-blocking (fast).")
        if submit_count > 0:
            print(f"Verified {submit_count} tasks submitted to background executor.")
        else:
            print("WARNING: No tasks submitted to background executor (unexpected for non-blocking impl).")
    else:
        print(f"FAILURE: Endpoint took {duration:.4f}s (blocking).")
        # Don't exit 1 here so we can see the output during baseline test
        # exit(1)

if __name__ == "__main__":
    benchmark()
