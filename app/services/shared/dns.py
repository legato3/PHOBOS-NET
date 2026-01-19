"""DNS resolution utilities."""
import time
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor
from app.config import DNS_SERVER, DNS_CACHE_MAX

# Global resolver instance
_shared_resolver = dns.resolver.Resolver()
# Only configure DNS if DNS_SERVER is provided
if DNS_SERVER:
    _shared_resolver.nameservers = [DNS_SERVER]
    _shared_resolver.timeout = 2
    _shared_resolver.lifetime = 2
else:
    # DNS disabled - resolver will not be used
    _shared_resolver = None

# DNS cache
_dns_cache = {}
_dns_ttl = {}
_dns_resolver_executor = ThreadPoolExecutor(max_workers=5)


def resolve_hostname(ip):
    """Resolve IP to hostname using configured DNS_SERVER."""
    # If DNS is disabled, return IP unchanged
    if not DNS_SERVER or _shared_resolver is None:
        return ip
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
    """Resolve IP to hostname with caching.
    
    Cache entries expire after 300 seconds (5 minutes).
    Background resolution is triggered for new IPs or expired cache entries.
    """
    now = time.time()
    cache_ttl = 300  # 5 minutes
    
    # Check if we have a valid cached result
    if ip in _dns_cache and now - _dns_ttl.get(ip, 0) < cache_ttl:
        return _dns_cache[ip] or ip
    
    # Trigger background resolution for new or expired entries
    # Use _dns_ttl to track last resolution attempt to avoid duplicate submissions
    last_attempt = _dns_ttl.get(ip, 0)
    if now - last_attempt >= cache_ttl:
        _dns_ttl[ip] = now  # Mark as attempting resolution
        if ip not in _dns_cache:
            _dns_cache[ip] = None  # Placeholder until resolved
        _dns_resolver_executor.submit(resolve_task, ip)
    
    return _dns_cache.get(ip) or ip