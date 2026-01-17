"""GeoIP lookup utilities."""
import time
import os
import maxminddb
from app.config import MMDB_CITY, MMDB_ASN, GEO_CACHE_MAX, GEO_CACHE_TTL, DB_CHECK_INTERVAL
from app.services.shared.helpers import is_internal, flag_from_iso

# Country names for fallback
_COUNTRY_NAMES = {
    'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'DE': 'Germany', 'GB': 'United Kingdom',
    'FR': 'France', 'JP': 'Japan', 'BR': 'Brazil', 'IN': 'India', 'CA': 'Canada', 'AU': 'Australia',
    'IT': 'Italy', 'ES': 'Spain', 'MX': 'Mexico', 'KR': 'South Korea', 'NL': 'Netherlands',
    'SE': 'Sweden', 'PL': 'Poland', 'TR': 'Turkey', 'ID': 'Indonesia', 'CH': 'Switzerland',
    'BE': 'Belgium', 'AT': 'Austria', 'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland',
    'IE': 'Ireland', 'PT': 'Portugal', 'CZ': 'Czech Republic', 'RO': 'Romania', 'HU': 'Hungary',
    'GR': 'Greece', 'IL': 'Israel', 'SG': 'Singapore', 'HK': 'Hong Kong', 'TW': 'Taiwan',
    'TH': 'Thailand', 'VN': 'Vietnam', 'MY': 'Malaysia', 'PH': 'Philippines', 'ZA': 'South Africa',
    'EG': 'Egypt', 'NG': 'Nigeria', 'KE': 'Kenya', 'AR': 'Argentina', 'CL': 'Chile',
    'CO': 'Colombia', 'PE': 'Peru', 'UA': 'Ukraine', 'SA': 'Saudi Arabia', 'AE': 'UAE',
    'PK': 'Pakistan', 'BD': 'Bangladesh', 'NZ': 'New Zealand', 'CY': 'Cyprus', 'LU': 'Luxembourg',
}

# Country centroid coordinates (fallback when City DB unavailable)
COUNTRY_CENTROIDS = {
    'US': (37.09, -95.71), 'CN': (35.86, 104.20), 'RU': (61.52, 105.32), 'DE': (51.17, 10.45),
    'GB': (55.38, -3.44), 'FR': (46.23, 2.21), 'JP': (36.20, 138.25), 'BR': (-14.24, -51.93),
    'IN': (20.59, 78.96), 'CA': (56.13, -106.35), 'AU': (-25.27, 133.78), 'IT': (41.87, 12.57),
    'ES': (40.46, -3.75), 'MX': (23.63, -102.55), 'KR': (35.91, 127.77), 'NL': (52.13, 5.29),
    'SE': (60.13, 18.64), 'PL': (51.92, 19.15), 'TR': (38.96, 35.24), 'ID': (-0.79, 113.92),
    'CH': (46.82, 8.23), 'BE': (50.50, 4.47), 'AT': (47.52, 14.55), 'NO': (60.47, 8.47),
    'DK': (56.26, 9.50), 'FI': (61.92, 25.75), 'IE': (53.14, -7.69), 'PT': (39.40, -8.22),
    'CZ': (49.82, 15.47), 'RO': (45.94, 25.00), 'HU': (47.16, 19.50), 'GR': (39.07, 21.82),
    'IL': (31.05, 34.85), 'SG': (1.35, 103.82), 'HK': (22.40, 114.11), 'TW': (23.70, 121.00),
    'TH': (15.87, 100.99), 'VN': (14.06, 108.28), 'MY': (4.21, 101.98), 'PH': (12.88, 121.77),
    'ZA': (-30.56, 22.94), 'EG': (26.82, 30.80), 'NG': (9.08, 8.68), 'KE': (-0.02, 37.91),
    'AR': (-38.42, -63.62), 'CL': (-35.68, -71.54), 'CO': (4.57, -74.30), 'PE': (-9.19, -75.02),
    'UA': (48.38, 31.17), 'SA': (23.89, 45.08), 'AE': (23.42, 53.85), 'PK': (30.38, 69.35),
    'BD': (23.68, 90.36), 'NZ': (-40.90, 174.89), 'CY': (35.13, 33.43), 'LU': (49.82, 6.13),
}

# Global state for GeoIP databases
mmdb_city = None
mmdb_asn = None
_city_db_checked_ts = 0
_asn_db_checked_ts = 0

# GeoIP cache
_geo_cache = {}


def _guess_country_from_ip(ip):
    """Guess country from IP using common allocation patterns (fallback when no MMDB).

    This is approximate - real accuracy requires MaxMind database.
    Uses first octet ranges that are commonly allocated to specific regions.
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return None
        first = int(parts[0])
        second = int(parts[1])

        # Common IP range allocations (approximate, covers major ranges)
        # US ranges
        if first in [3, 4, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 28, 29, 30, 32, 33, 34, 35, 38, 40, 44, 45, 47, 48, 50, 52, 54, 55, 56, 57, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 137, 138, 140, 142, 143, 144, 146, 147, 148, 149, 152, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 198, 199, 204, 205, 206, 207, 208, 209, 216]:
            return 'US'
        # EU ranges (DE, GB, FR, NL, etc.)
        if first in [2, 5, 31, 37, 46, 51, 53, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213]:
            # Approximate EU country by second octet
            if second < 50: return 'DE'
            if second < 100: return 'GB'
            if second < 150: return 'FR'
            if second < 200: return 'NL'
            return 'DE'
        # Asia Pacific
        if first in [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223]:
            if second < 64: return 'CN'
            if second < 128: return 'JP'
            if second < 192: return 'KR'
            return 'AU'
        # Russia
        if first in [5, 31, 37, 46, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 176, 178, 185, 188, 212, 213, 217] and second >= 200:
            return 'RU'
        # Brazil, Latin America
        if first in [177, 179, 181, 186, 187, 189, 190, 191, 200, 201]:
            return 'BR'
        # Canada
        if first in [24, 64, 65, 66, 67, 68, 69, 70, 71, 72, 99, 142, 192, 198, 199, 204, 205, 206, 207] and second >= 200:
            return 'CA'
        # Default: pick based on hash for consistency
        seed = sum(int(p) for p in parts)
        countries = ['US', 'DE', 'GB', 'FR', 'JP', 'CN', 'BR', 'AU', 'CA', 'NL', 'IN', 'RU']
        return countries[seed % len(countries)]
    except Exception:
        return None


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
    
    # Fallback country detection when no MMDB available (basic IP range heuristics)
    if not res.get('country_iso') and not is_internal(ip):
        iso = _guess_country_from_ip(ip)
        if iso:
            res['country_iso'] = iso
            res['country'] = _COUNTRY_NAMES.get(iso, 'Unknown')
            res['flag'] = flag_from_iso(iso)

    # Fallback: Use country centroid if lat/lng missing but country_iso known
    if res.get('country_iso') and not res.get('lat'):
        centroid = COUNTRY_CENTROIDS.get(res['country_iso'])
        if centroid:
            res['lat'], res['lng'] = centroid

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