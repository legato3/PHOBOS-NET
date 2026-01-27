import sys
sys.path.insert(0, ".")
# Mock app context and config
from unittest.mock import MagicMock
import sys
sys.modules['app.core.app_state'] = MagicMock()
sys.modules['app.core.app_state']._syslog_stats_lock = MagicMock()
sys.modules['app.core.app_state']._syslog_stats = {}
sys.modules['app.core.app_state']._flow_history_lock = MagicMock()
sys.modules['app.core.app_state']._flow_history = {}

from app.services.pulse.feed import _pulse_generator, PulseEvent
from app.db.sqlite import _firewall_db_init, _firewall_db_connect

# Init DB
try:
    _firewall_db_init()
except Exception as e:
    print(f"DB init warning (might be mocked): {e}")

# Check if generator can tick
try:
    _pulse_generator.tick()
    print("Pulse tick successful")
except Exception as e:
    print(f"Pulse tick failed: {e}")
    import traceback
    traceback.print_exc()
