"""
Service name resolution with caching and locking optimizations.
"""
import socket
from app.core.app_state import _service_cache, _lock_service_cache
from app.config import PORTS

def resolve_service_name(port_val, proto_val):
    """Resolve service name with caching and double-checked locking optimization."""
    try:
        port_num = int(port_val)
        proto = 'tcp' if '6' in str(proto_val) else 'udp'

        # 1. Check static configuration (fastest, no lock)
        if port_num in PORTS:
            return PORTS[port_num]

        service_key = (port_num, proto)

        # 2. Check cache optimistically (fast, no lock)
        svc = _service_cache.get(service_key)
        if svc:
            return svc

        # 3. Cache miss: Acquire lock and double-check
        with _lock_service_cache:
            svc = _service_cache.get(service_key)
            if svc is None:
                try:
                    svc = socket.getservbyport(port_num, proto)
                except OSError:
                    svc = str(port_num) # Fallback
                _service_cache[service_key] = svc
        return svc

    except (ValueError, TypeError):
        return str(port_val) # Return original if not a valid integer
