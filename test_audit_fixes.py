
import unittest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Add app to path
sys.path.append(os.getcwd())

from flask import Flask
from app.api.routes import bp
import app.services.threats as threats_module

class TestAuditFixes(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    @patch('app.api.routes.get_common_nfdump_data')
    def test_api_risk_index_external_exposure(self, mock_get_data):
        # Mock sources data to simulate high external traffic
        mock_get_data.return_value = [
            {'key': '8.8.8.8', 'bytes': 60 * 1024 * 1024, 'internal': False}, # > 50MB
            {'key': '192.168.1.50', 'bytes': 100, 'internal': True}
        ]

        # We need to patch is_internal used inside api_risk_index logic if it's not mocked by get_common_nfdump_data return
        # The route uses: s.get('internal', False) and not is_internal(s.get('key', ''))
        # So providing 'internal': False in mock data is good start, but let's ensure is_internal behaves

        with patch('app.api.routes.is_internal', return_value=False):
            response = self.client.get('/api/security/risk_index')
            data = response.get_json()

            # Find the "External Exposure" factor
            factors = data.get('factors', [])
            exposure_factor = next((f for f in factors if f['factor'] == 'External Exposure'), None)

            self.assertIsNotNone(exposure_factor, "External Exposure factor should exist")
            self.assertEqual(exposure_factor['value'], '> 50MB', "Should detect > 50MB traffic")

    @patch('app.api.routes.run_nfdump')
    @patch('app.api.routes.load_threatlist')
    @patch('app.api.routes.load_watchlist')
    @patch('app.api.routes.is_internal')
    def test_api_compromised_hosts_roles(self, mock_is_internal, mock_watchlist, mock_threatlist, mock_nfdump):
        # Mock threat list
        mock_threatlist.return_value = {'1.1.1.1'}
        mock_watchlist.return_value = set()

        # Mock nfdump output (CSV format)
        # Columns: ts, td, pr, sa, da, sp, dp, ipkt, ibyt, fl
        # Route expects: srcip, dstip, dstport, bytes, flows
        # -O bytes -A srcip,dstip,dstport -n 2000
        # Output format: ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr
        # Actually route uses: parts[sa_idx], parts[da_idx]...
        # Let's verify indices in route: sa=3, da=4, dp=6, ibyt=8, fl=9 (default)

        # Case 1: Inbound from Threat (Threat 1.1.1.1 -> Internal 192.168.1.10)
        # Case 2: Outbound to Threat (Internal 192.168.1.10 -> Threat 1.1.1.1)

        csv_output = "\n".join([
            "ts,td,pr,sa,da,sp,dp,ipkt,ibyt,fl",
            "2023-01-01 10:00:00,1.0,6,1.1.1.1,192.168.1.10,80,12345,10,1000,1", # Inbound
            "2023-01-01 10:00:00,1.0,6,192.168.1.10,1.1.1.1,12345,80,10,1000,1"  # Outbound
        ])
        mock_nfdump.return_value = csv_output

        # Mock is_internal logic
        def side_effect_is_internal(ip):
            return ip.startswith('192.168.')
        mock_is_internal.side_effect = side_effect_is_internal

        response = self.client.get('/api/security/compromised_hosts')
        data = response.get_json()

        hosts = data.get('hosts', [])
        # Since we have same internal IP involved in both directions, logic might merge or pick dominant
        # The route logic: "if bytes_val > entry['max_bytes']: entry['direction'] = direction"
        # Since bytes are equal (1000), behavior depends on order.
        # But wait, compromised hosts list is keyed by internal IP.
        # Let's ensure we return at least one host and check the role label format.

        self.assertTrue(len(hosts) > 0)
        role = hosts[0]['role']
        self.assertIn(role, ["Inbound from Threat", "Outbound to Threat"], f"Role '{role}' should be descriptive")

    @patch('app.api.routes.get_common_nfdump_data')
    def test_api_protocol_anomalies_status(self, mock_get_data):
        mock_get_data.return_value = [] # No protocols needed for status check

        # Mock global state in threats module
        # Accessing private globals via module
        original_baseline = threats_module._protocol_baseline
        threats_module._protocol_baseline = {} # Empty baseline -> warming

        try:
            response = self.client.get('/api/security/protocol-anomalies')
            data = response.get_json()

            self.assertEqual(data['status'], 'warming', "Status should be 'warming' with empty baseline")

            # Now simulate active
            threats_module._protocol_baseline = {'TCP': {'samples': 60, 'total_bytes': 1000}}
            response = self.client.get('/api/security/protocol-anomalies')
            data = response.get_json()
            self.assertEqual(data['status'], 'active', "Status should be 'active' with >50 samples")

        finally:
            threats_module._protocol_baseline = original_baseline

if __name__ == '__main__':
    unittest.main()
