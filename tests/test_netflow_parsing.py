
import unittest
import sys
from unittest.mock import MagicMock
from types import ModuleType
import os

# Helpers to mock packages and modules
def mock_module(module_name):
    sys.modules[module_name] = MagicMock()

# Mock external dependencies
mock_module('flask')
mock_module('flask_compress')
mock_module('requests')
mock_module('maxminddb')

# Mock dns package structure
dns_pkg = ModuleType('dns')
dns_pkg.__path__ = []
sys.modules['dns'] = dns_pkg
mock_module('dns.resolver')
mock_module('dns.reversename')

# Mock app.core.app_state which is used by netflow.py
mock_module('app.core.app_state')

# Mock app.services.shared.ingestion_metrics which is used by netflow.py
mock_module('app.services.shared.ingestion_metrics')
mock_module('app.services.shared.metrics')
mock_module('app.services.shared.observability')

# Mock app.api.routes to avoid blueprints
mock_module('app.api')
mock_module('app.api.routes')
mock_module('app.api.routes.firewall_decisions')

# Mock app.config
mock_module('app.config')
sys.modules['app.config'].DEFAULT_TIMEOUT = 10
sys.modules['app.config'].SAMPLE_DATA_PATH = "sample_data/nfdump_flows.csv"
sys.modules['app.config'].COMMON_DATA_CACHE_MAX = 100
sys.modules['app.config'].NFCAPD_DIR = "/var/cache/nfdump"
sys.modules['app.config'].OBS_ROUTE_SLOW_MS = 1000
sys.modules['app.config'].OBS_ROUTE_SLOW_WARN_MS = 2000

# Setup Fake Packages for app structure
app_fake = ModuleType('app')
app_fake.__path__ = [os.path.abspath('app')]
sys.modules['app'] = app_fake

core_fake = ModuleType('app.core')
core_fake.__path__ = [os.path.abspath('app/core')]
sys.modules['app.core'] = core_fake

services_fake = ModuleType('app.services')
services_fake.__path__ = [os.path.abspath('app/services')]
sys.modules['app.services'] = services_fake

netflow_fake = ModuleType('app.services.netflow')
netflow_fake.__path__ = [os.path.abspath('app/services/netflow')]
sys.modules['app.services.netflow'] = netflow_fake

try:
    from app.services.netflow.netflow import parse_csv
except ImportError as e:
    print(f"Import failed: {e}")
    sys.exit(1)

class TestNetflowParsing(unittest.TestCase):
    def test_parse_csv_basic(self):
        header = "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr"
        row = "2023-01-01 10:00:00,2023-01-01 10:01:00,60,192.168.1.1,10.0.0.1,1234,80,6,......,0,0,10,1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        output = f"{header}\n{row}"

        results = parse_csv(output, expected_key='sa')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['key'], "192.168.1.1")
        self.assertEqual(results[0]['bytes'], 1000)

    def test_parse_csv_summary(self):
        header = "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr"
        row = "2023-01-01 10:00:00,2023-01-01 10:01:00,60,192.168.1.1,10.0.0.1,1234,80,6,......,0,0,10,1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        summary = "Sys: 0.123s flows/second: 123.4"
        output = f"{header}\n{row}\n{summary}"

        results = parse_csv(output, expected_key='sa')
        self.assertEqual(len(results), 1)

    def test_parse_csv_headers_repeat(self):
        header = "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr"
        row = "2023-01-01 10:00:00,2023-01-01 10:01:00,60,192.168.1.1,10.0.0.1,1234,80,6,......,0,0,10,1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        row2 = "2023-01-01 10:00:00,2023-01-01 10:01:00,60,192.168.1.2,10.0.0.1,1234,80,6,......,0,0,10,1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        output = f"{header}\n{row}\n{header}\n{row2}"

        results = parse_csv(output, expected_key='sa')
        self.assertEqual(len(results), 2)
        keys = set(r['key'] for r in results)
        self.assertIn("192.168.1.1", keys)
        self.assertIn("192.168.1.2", keys)

if __name__ == '__main__':
    unittest.main()
