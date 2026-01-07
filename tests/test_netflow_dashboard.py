
import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import json
import time

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock modules that might not be available or side-effect heavy
sys.modules['maxminddb'] = MagicMock()

# Import the module
import importlib
try:
    netflow_dashboard = importlib.import_module("netflow-dashboard")
except ImportError:
    # Handle the case where the file is named netflow-dashboard.py which is not a valid module name
    # We load it using source file loader
    import importlib.util
    spec = importlib.util.spec_from_file_location("netflow_dashboard", "netflow-dashboard.py")
    netflow_dashboard = importlib.util.module_from_spec(spec)
    sys.modules["netflow_dashboard"] = netflow_dashboard
    spec.loader.exec_module(netflow_dashboard)

class TestNetflowDashboard(unittest.TestCase):
    def setUp(self):
        self.app = netflow_dashboard.app.test_client()
        self.app.testing = True

    @patch('netflow_dashboard.subprocess.run')
    def test_api_overview(self, mock_run):

        def side_effect(cmd, **kwargs):
            # parse cmd to see what we need
            # cmd is list
            output = ""
            # The header must include 'ip' to be detected as key by heuristic, or match default indices.
            # And sufficient columns.
            if "srcip/bytes/flows/packets" in cmd[0] or any("srcip" in c for c in cmd):
                output = "ip,flows,packets,bytes\n192.168.1.1,10,100,1000\n10.0.0.1,5,50,500"
            elif "dstip/bytes" in cmd[0] or any("dstip" in c for c in cmd):
                output = "ip,flows,packets,bytes\n8.8.8.8,10,100,1000"
            elif "dstport/bytes" in cmd[0] or any("dstport" in c for c in cmd):
                output = "port,flows,packets,bytes\n80,10,100,1000"
            elif "proto/bytes" in cmd[0] or any("proto" in c for c in cmd):
                output = "proto,flows,packets,bytes\n6,10,100,1000"
            else:
                output = "ip,flows,packets,bytes\nunknown,0,0,0"

            m = MagicMock()
            m.returncode = 0
            m.stdout = output
            return m

        mock_run.side_effect = side_effect

        response = self.app.get('/api/overview')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('top_sources', data)
        self.assertEqual(len(data['top_sources']), 2)

    @patch('netflow_dashboard.subprocess.run')
    def test_api_bandwidth(self, mock_run):
        def side_effect(cmd, **kwargs):
            output = "proto,flows,packets,bytes\nTCP,100,1000,50000"
            m = MagicMock()
            m.returncode = 0
            m.stdout = output
            return m
        mock_run.side_effect = side_effect

        # Call multiple times to test caching and future coalescence
        response = self.app.get('/api/bandwidth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('bandwidth', data)
        self.assertEqual(len(data['bandwidth']), 12)

        response = self.app.get('/api/bandwidth')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
