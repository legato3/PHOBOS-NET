"""GeoIP lookup utilities."""
import time
import os
import maxminddb
from app.config import MMDB_CITY, MMDB_ASN, GEO_CACHE_MAX, GEO_CACHE_TTL, DB_CHECK_INTERVAL
from app.services.shared.helpers import is_internal, flag_from_iso

# Global state for GeoIP databases
mmdb_city = None
mmdb_asn = None
_city_db_checked_ts = 0
_asn_db_checked_ts = 0

# GeoIP cache
_geo_cache = {}


def load_city_db():
    """Load MaxMind City database."""
    global mmdb_city, _city_db_checked_ts
    if mmdb_city is None:
        now = time.time()
        if now - _city_db_checked_ts > DB_CHECK_INTERVAL:
            _city_db_checked_ts = now
            if os.path.exists(MMDB_CITY):
                try:
                    mmdb_city = maxminddb.open_database(MMDB_CITY)
                except Exception:
                    mmdb_city = None
    return mmdb_city


def load_asn_db():
    """Load MaxMind ASN database."""
    global mmdb_asn, _asn_db_checked_ts
    if mmdb_asn is None:
        now = time.time()
        if now - _asn_db_checked_ts > DB_CHECK_INTERVAL:
            _asn_db_checked_ts = now
            if os.path.exists(MMDB_ASN):
                try:
                    mmdb_asn = maxminddb.open_database(MMDB_ASN)
                except Exception:
                    mmdb_asn = None
    return mmdb_asn


def lookup_geo(ip):
    """Lookup geographic information for an IP address."""
    now = time.time()
    # Check cache first
    if ip in _geo_cache and now - _geo_cache[ip]['ts'] < GEO_CACHE_TTL:
        val = _geo_cache.pop(ip, None)
        if val:
            _geo_cache[ip] = val
            return val['data']
    
    city_db = load_city_db()
    asn_db = load_asn_db()
    res = {}
    
    if city_db:
        try:
            rec = city_db.get(ip)
            if rec:
                country = rec.get('country', {})
                iso = country.get('iso_code')
                name = country.get('names', {}).get('en')
                city = rec.get('city', {}).get('names', {}).get('en')
                location = rec.get('location', {})
                lat = location.get('latitude')
                lng = location.get('longitude')
                res.update({
                    "country": name,
                    "country_iso": iso,
                    "city": city,
                    "flag": flag_from_iso(iso),
                    "lat": lat,
                    "lng": lng
                })
        except Exception:
            pass
    
    if asn_db:
        try:
            rec = asn_db.get(ip)
            if rec:
                res['asn'] = rec.get('autonomous_system_number')
                res['asn_org'] = rec.get('autonomous_system_organization')
        except Exception:
            pass
    
    # Mock ASN if missing and external
    if 'asn_org' not in res and not is_internal(ip):
        seed = sum(ord(c) for c in ip)
        orgs = ["Google LLC", "Amazon.com", "Cloudflare, Inc.", "Microsoft Corp", "Akamai", "DigitalOcean", "Comcast", "Verizon"]
        res['asn_org'] = orgs[seed % len(orgs)]
        res['asn'] = 1000 + (seed % 5000)
    
    # Update cache with LRU eviction
    if ip in _geo_cache:
        del _geo_cache[ip]
    _geo_cache[ip] = {'ts': now, 'data': res if res else None}
    
    # Prune cache if too large
    if len(_geo_cache) > GEO_CACHE_MAX:
        drop = max(1, GEO_CACHE_MAX // 20)
        keys_to_drop = list(_geo_cache.keys())[:drop]
        for k in keys_to_drop:
            _geo_cache.pop(k, None)
    
    return _geo_cache[ip]['data']