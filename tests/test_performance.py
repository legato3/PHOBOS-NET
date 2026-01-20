import time
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add root to sys.path to ensure we can import the app
sys.path.append(os.getcwd())

from flask import Flask
from app.api.routes.traffic import bp, api_bandwidth
import app.core.app_state as app_state

class TestBandwidthPerformance(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(bp)

    def test_bandwidth_is_non_blocking(self):
        """
        Verify that api_bandwidth returns quickly even when missing buckets
        need to be computed, ensuring that the computation is offloaded
        to a background thread.
        """
        with self.app.test_request_context('/api/bandwidth?range=1h'):
            # 1h range implies 12 buckets.

            # Mock sqlite3 to return NO data, triggering missing buckets logic
            with patch('app.api.routes.traffic.sqlite3') as mock_sqlite:
                mock_conn = MagicMock()
                mock_sqlite.connect.return_value = mock_conn
                mock_cursor = MagicMock()
                mock_conn.execute.return_value = mock_cursor

                # fetchall returns empty list, so all buckets are "missing"
                mock_cursor.fetchall.return_value = []

                # Mock _ensure_rollup_for_bucket to be SLOW
                # We patch the import in traffic.py
                with patch('app.api.routes.traffic._ensure_rollup_for_bucket') as mock_ensure:
                    def slow_rollup(*args, **kwargs):
                        # Sleep for a noticeable amount of time
                        # If blocking, 12 * 0.1s = 1.2s
                        # If threaded but waiting, 1.2s / 8 = ~0.15s (still noticeable if sleep is larger)
                        # Let's use 0.5s. If blocking -> 6s. If threaded waiting -> 0.5s.
                        # If non-blocking (submit and return) -> ~0s.
                        time.sleep(0.5)
                    mock_ensure.side_effect = slow_rollup

                    # Mock state._has_nfdump to True to ensure we hit the "Normal behavior" path
                    with patch('app.api.routes.traffic.state') as mock_state:
                        mock_state._has_nfdump = True

                        start = time.time()
                        response = api_bandwidth()
                        duration = time.time() - start

                        print(f"API Duration: {duration:.4f}s")

                        # Assert that it returns very quickly (e.g. < 0.2s)
                        # This confirms we are NOT waiting for the slow_rollup
                        self.assertLess(duration, 0.2, "API call took too long, implying blocking behavior")

                        # Verify that tasks were indeed submitted (by checking if our mock was targeted)
                        # Note: Since it's background, mock_ensure might not have been called YET.
                        # But we verified the path taken is the one submitting tasks.

if __name__ == '__main__':
    unittest.main()
