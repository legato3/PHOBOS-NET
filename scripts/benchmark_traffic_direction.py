
import sys
import time
import types
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

# Setup app.core.app_state using a real class
class MockAppState:
    _metric_nfdump_calls = 0
    _has_nfdump = True
    def add_app_log(self, *args, **kwargs):
        pass
    _nfdump_executor = ThreadPoolExecutor(max_workers=8)

state_mock = MockAppState()

# Mock dependencies properly
app = types.ModuleType('app')
sys.modules['app'] = app

app_config = types.ModuleType('app.config')
app_config.DEFAULT_TIMEOUT = 10
app_config.SAMPLE_DATA_PATH = '/tmp'
app_config.COMMON_DATA_CACHE_MAX = 100
app_config.NFCAPD_DIR = '/tmp'
sys.modules['app.config'] = app_config

app_core = types.ModuleType('app.core')
app_core.app_state = state_mock
sys.modules['app.core'] = app_core
sys.modules['app.core.app_state'] = state_mock

app_services = types.ModuleType('app.services')
sys.modules['app.services'] = app_services

# For others we can use MagicMock if we don't need structure
sys.modules['app.services.shared'] = MagicMock()
sys.modules['app.services.shared.helpers'] = MagicMock()
sys.modules['app.services.shared.observability'] = MagicMock()
sys.modules['app.services.shared.metrics'] = MagicMock()
sys.modules['app.services.shared.ingestion_metrics'] = MagicMock()
sys.modules['app.db'] = MagicMock()
sys.modules['app.db.sqlite'] = MagicMock()


# Load netflow module
import importlib.util
spec = importlib.util.spec_from_file_location("app.services.netflow.netflow", "app/services/netflow/netflow.py")
netflow = importlib.util.module_from_spec(spec)
sys.modules["app.services.netflow.netflow"] = netflow
spec.loader.exec_module(netflow)

print(f"DEBUG: netflow.state type: {type(netflow.state)}")
print(f"DEBUG: netflow.state._nfdump_executor type: {type(netflow.state._nfdump_executor)}")

# Patch stream_nfdump to simulate delay
def mock_stream_nfdump(args, tf=None):
    time.sleep(0.01) # Simulate 10ms nfdump execution
    yield "ts,te,td,sa,da,sp,dp,pr,fl,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr"
    yield "2023-01-01 10:00:00,2023-01-01 10:00:01,1.0,1.2.3.4,5.6.7.8,123,456,6,1,0,0,10,1000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"

netflow.stream_nfdump = mock_stream_nfdump

def run_benchmark():
    iterations = 100
    ip = "1.2.3.4"
    tf = "10m"

    # Benchmark Refactored Implementation (Using Shared Executor)
    start_time = time.time()
    for _ in range(iterations):
        # Clear cache
        with netflow._traffic_direction_lock:
            netflow._traffic_direction_cache.clear()

        try:
            netflow.get_traffic_direction(ip, tf)
        except Exception as e:
            print(f"Error caught: {e}")
            break

    duration = time.time() - start_time
    print(f"Refactored Implementation (Shared Executor): {duration:.4f}s for {iterations} iterations")

if __name__ == "__main__":
    run_benchmark()
