"""DNS resolution utilities."""
import time
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor
from app.config import DNS_SERVER, DNS_CACHE_MAX

# Global resolver instance
_shared_resolver = dns.resolver.Resolver()
_shared_resolver.nameservers = [DNS_SERVER]
_shared_resolver.timeout = 2
_shared_resolver.lifetime = 2

# DNS cache
_dns_cache = {}
_dns_ttl = {}
_dns_resolver_executor = ThreadPoolExecutor(max_workers=5)


def resolve_hostname(ip):
    """Resolve IP to hostname using configured DNS_SERVER."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = _shared_resolver.resolve(rev_name, 'PTR')
        return str(answer[0]).rstrip('.')
    except Exception:
        return ip


def resolve_task(ip):
    """Background task to resolve hostname."""
    try:
        hostname = resolve_hostname(ip)
        if hostname != ip:
            _dns_cache[ip] = hostname
            _dns_ttl[ip] = time.time()
            # Prune cache if too large
            if len(_dns_cache) > DNS_CACHE_MAX:
                items = sorted(_dns_ttl.items(), key=lambda kv: kv[1])
                for k, _ in items[:max(1, DNS_CACHE_MAX // 20)]:
                    _dns_cache.pop(k, None)
                    _dns_ttl.pop(k, None)
    except Exception:
        pass


def resolve_ip(ip):
    """Resolve IP to hostname with caching."""
    now = time.time()
    if ip in _dns_cache and now - _dns_ttl.get(ip, 0) < 300:
        return _dns_cache[ip] or ip
    
    # Trigger background resolution
    if ip not in _dns_cache:
        _dns_cache[ip] = None
        _dns_ttl[ip] = now
        _dns_resolver_executor.submit(resolve_task, ip)
    
    return _dns_cache.get(ip) or ip