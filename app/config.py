"""Configuration module for PROX_NFDUMP application."""
import os

# Application Metadata (Single Source of Truth)
APP_NAME = "PHOBOS-NET"
APP_VERSION = "v1.0.0"
APP_VERSION_DISPLAY = "v1.0"  # Human-readable version for UI

# Cache TTLs
CACHE_TTL_SHORT = 30        # 30 seconds for fast-changing data
CACHE_TTL_THREAT = 900      # 15 minutes for threat feeds
DEFAULT_TIMEOUT = 25        # subprocess timeout
MAX_RESULTS = 100           # default limit for API results
DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

# Observability thresholds (configurable via environment variables)
OBS_NFDUMP_WARN_MS = float(os.getenv('OBS_NFDUMP_WARN_MS', '5000'))  # Warn if nfdump > 5s
OBS_CACHE_MISS_RATE_WARN = float(os.getenv('OBS_CACHE_MISS_RATE_WARN', '0.5'))  # Warn if miss rate > 50%
OBS_ROUTE_SLOW_MS = float(os.getenv('OBS_ROUTE_SLOW_MS', '1000'))  # Flag route as slow if > 1s
OBS_ROUTE_SLOW_WARN_MS = float(os.getenv('OBS_ROUTE_SLOW_WARN_MS', '2000'))  # Warn if route > 2s
OBS_SERVICE_SLOW_MS = float(os.getenv('OBS_SERVICE_SLOW_MS', '500'))  # Warn if service function > 500ms

# Paths
MMDB_CITY = "/root/GeoLite2-City.mmdb"
MMDB_ASN = "/root/GeoLite2-ASN.mmdb"
THREATLIST_PATH = "/root/threat-ips.txt"
THREAT_FEED_URL_PATH = "/root/threat-feed.url"
THREAT_WHITELIST = "/root/threat-whitelist.txt"
WEBHOOK_PATH = "/root/netflow-webhook.url"
SMTP_CFG_PATH = os.getenv("SMTP_CFG_PATH", "/root/netflow-smtp.json")
NOTIFY_CFG_PATH = os.getenv("NOTIFY_CFG_PATH", "/root/netflow-notify.json")
THRESHOLDS_CFG_PATH = os.getenv("THRESHOLDS_CFG_PATH", "/root/netflow-thresholds.json")
CONFIG_PATH = os.getenv("CONFIG_PATH", "/root/netflow-config.json")
SAMPLE_DATA_PATH = "sample_data/nfdump_flows.csv"
WATCHLIST_PATH = "/root/watchlist.txt"
SECURITY_WEBHOOK_PATH = "/root/security-webhook.json"

# Database paths
TRENDS_DB_PATH = os.getenv("TRENDS_DB_PATH", "netflow-trends.sqlite")
_env_fw_db = os.getenv("FIREWALL_DB_PATH")
if _env_fw_db and _env_fw_db.strip():
    FIREWALL_DB_PATH = _env_fw_db
else:
    _default_fw_db = "/root/firewall.db"
    _fw_dir = os.path.dirname(_default_fw_db) or "/"
    if os.path.isdir(_fw_dir) and os.access(_fw_dir, os.W_OK):
        FIREWALL_DB_PATH = _default_fw_db
    else:
        FIREWALL_DB_PATH = os.path.join(os.getcwd(), "firewall.db")

# Syslog configuration
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
SYSLOG_BIND = os.getenv("SYSLOG_BIND", "0.0.0.0")
FIREWALL_IP = os.getenv("FIREWALL_IP", "192.168.0.1")
FIREWALL_RETENTION_DAYS = 7
SYSLOG_BUFFER_SIZE = 100

# DNS Configuration
DNS_SERVER = os.getenv("DNS_SERVER", "192.168.0.6")
DNS_CACHE_MAX = 5000

# SNMP Configuration
SNMP_HOST = os.getenv("SNMP_HOST", "192.168.0.1")
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "Phoboshomesnmp_3")
SNMP_POLL_INTERVAL = float(os.getenv("SNMP_POLL_INTERVAL", "2"))  # seconds
SNMP_CACHE_TTL = float(os.getenv("SNMP_CACHE_TTL", str(max(1.0, SNMP_POLL_INTERVAL))))

# SNMP OIDs
SNMP_OIDS = {
    "cpu_load_1min": ".1.3.6.1.4.1.2021.10.1.3.1",
    "cpu_load_5min": ".1.3.6.1.4.1.2021.10.1.3.2",
    "mem_total": ".1.3.6.1.4.1.2021.4.5.0",        # Total RAM KB
    "mem_avail": ".1.3.6.1.4.1.2021.4.6.0",        # Available RAM KB
    "mem_buffer": ".1.3.6.1.4.1.2021.4.11.0",       # Buffer memory KB
    "mem_cached": ".1.3.6.1.4.1.2021.4.15.0",       # Cached memory KB
    # Swap
    "swap_total": ".1.3.6.1.4.1.2021.4.3.0",       # Total swap KB
    "swap_avail": ".1.3.6.1.4.1.2021.4.4.0",       # Available swap KB
    "sys_uptime": ".1.3.6.1.2.1.1.3.0",            # Uptime timeticks
    "tcp_conns": ".1.3.6.1.2.1.6.9.0",             # tcpCurrEstab
    "tcp_active_opens": ".1.3.6.1.2.1.6.5.0",      # tcpActiveOpens
    "tcp_estab_resets": ".1.3.6.1.2.1.6.8.0",      # tcpEstabResets
    "proc_count": ".1.3.6.1.2.1.25.1.6.0",         # hrSystemProcesses
    "if_wan_status": ".1.3.6.1.2.1.2.2.1.8.1",     # igc0 operStatus
    "if_lan_status": ".1.3.6.1.2.1.2.2.1.8.2",     # igc1 operStatus
    "if_wan_admin": ".1.3.6.1.2.1.2.2.1.7.1",     # igc0 adminStatus
    "if_lan_admin": ".1.3.6.1.2.1.2.2.1.7.2",     # igc1 adminStatus
    "tcp_fails": ".1.3.6.1.2.1.6.7.0",             # tcpAttemptFails
    "tcp_retrans": ".1.3.6.1.2.1.6.12.0",          # tcpRetransSegs
    # IP stack
    "ip_in_discards": ".1.3.6.1.2.1.4.8.0",        # ipInDiscards
    "ip_in_hdr_errors": ".1.3.6.1.2.1.4.4.0",      # ipInHdrErrors
    "ip_in_addr_errors": ".1.3.6.1.2.1.4.5.0",     # ipInAddrErrors
    "ip_forw_datagrams": ".1.3.6.1.2.1.4.6.0",     # ipForwDatagrams
    "ip_in_delivers": ".1.3.6.1.2.1.4.9.0",        # ipInDelivers
    "ip_out_requests": ".1.3.6.1.2.1.4.10.0",      # ipOutRequests
    # ICMP
    "icmp_in_errors": ".1.3.6.1.2.1.5.2.0",        # icmpInErrors
    "wan_in": ".1.3.6.1.2.1.31.1.1.1.6.1",         # igc0 in
    "wan_out": ".1.3.6.1.2.1.31.1.1.1.10.1",       # igc0 out
    "lan_in": ".1.3.6.1.2.1.31.1.1.1.6.2",         # igc1 in
    "lan_out": ".1.3.6.1.2.1.31.1.1.1.10.2",       # igc1 out
    # Interface speeds (Mbps)
    "wan_speed": ".1.3.6.1.2.1.31.1.1.1.15.1",     # ifHighSpeed WAN
    "lan_speed": ".1.3.6.1.2.1.31.1.1.1.15.2",     # ifHighSpeed LAN
    # Interface errors/discards (32-bit but fine for error counters)
    "wan_in_err": ".1.3.6.1.2.1.2.2.1.14.1",
    "wan_out_err": ".1.3.6.1.2.1.2.2.1.20.1",
    "wan_in_disc": ".1.3.6.1.2.1.2.2.1.13.1",
    "wan_out_disc": ".1.3.6.1.2.1.2.2.1.19.1",
    "lan_in_err": ".1.3.6.1.2.1.2.2.1.14.2",
    "lan_out_err": ".1.3.6.1.2.1.2.2.1.20.2",
    "lan_in_disc": ".1.3.6.1.2.1.2.2.1.13.2",
    "lan_out_disc": ".1.3.6.1.2.1.2.2.1.19.2",
    "disk_read": ".1.3.6.1.4.1.2021.13.15.1.1.12.2", # nda0 read bytes
    "disk_write": ".1.3.6.1.4.1.2021.13.15.1.1.13.2", # nda0 write bytes
    "udp_in": ".1.3.6.1.2.1.7.1.0",                # udpInDatagrams
    "udp_out": ".1.3.6.1.2.1.7.4.0",               # udpOutDatagrams
}

# Threat Intelligence API Keys (optional)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
THREAT_INTEL_CACHE_TTL = 3600  # 1 hour

# Cache sizes
GEO_CACHE_MAX = 2000
GEO_CACHE_TTL = 900  # 15 minutes
COMMON_DATA_CACHE_MAX = 100
DB_CHECK_INTERVAL = 60

# Network configuration
INTERNAL_NETS = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                 "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", 
                 "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

# Port and protocol mappings
PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 3389: "RDP",
    5900: "VNC", 27017: "MongoDB", 1194: "OpenVPN", 51820: "WireGuard"
}

PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH"}

SUSPICIOUS_PORTS = [4444, 5555, 6667, 8888, 9001, 9050, 9150, 31337, 12345, 1337, 666, 6666]

# Detection thresholds
BRUTE_FORCE_PORTS = [22, 23, 3389, 5900, 21, 25, 110, 143, 993, 995, 3306, 5432]
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 300  # 5 minutes
EXFIL_THRESHOLD_MB = 500
EXFIL_RATIO_THRESHOLD = 10
DNS_QUERY_THRESHOLD = 100
DNS_TXT_THRESHOLD = 20
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 22
OFF_HOURS_THRESHOLD_MB = 100

# Phase 2: Long-lived low-volume external flow detection thresholds
# Detection: flows with duration > DURATION_THRESHOLD seconds AND bytes < BYTES_THRESHOLD AND external (not internal)
LONG_LOW_DURATION_THRESHOLD = float(os.getenv('LONG_LOW_DURATION_THRESHOLD', '300'))  # 5 minutes default
LONG_LOW_BYTES_THRESHOLD = int(os.getenv('LONG_LOW_BYTES_THRESHOLD', '100000'))  # 100 KB default

# Baseline tracking configuration
BASELINE_WINDOW_SIZE = int(os.getenv('BASELINE_WINDOW_SIZE', '100'))  # Number of samples in rolling window
BASELINE_UPDATE_INTERVAL = int(os.getenv('BASELINE_UPDATE_INTERVAL', '300'))  # Update every 5 minutes (300s)
BASELINE_DEVIATION_MULTIPLIER = float(os.getenv('BASELINE_DEVIATION_MULTIPLIER', '2.0'))  # 2 standard deviations = abnormal

# MITRE ATT&CK mappings
MITRE_MAPPINGS = {
    'C2': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    'MALWARE': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'SCANNER': {'technique': 'T1595', 'tactic': 'Reconnaissance', 'name': 'Active Scanning'},
    'BADACTOR': {'technique': 'T1190', 'tactic': 'Initial Access', 'name': 'Exploit Public-Facing Application'},
    'COMPROMISED': {'technique': 'T1584', 'tactic': 'Resource Development', 'name': 'Compromise Infrastructure'},
    'HIJACKED': {'technique': 'T1583', 'tactic': 'Resource Development', 'name': 'Acquire Infrastructure'},
    'AGGREGATE': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    'TOR': {'technique': 'T1090', 'tactic': 'Command and Control', 'name': 'Proxy'},
}

# Region mappings
REGION_MAPPING = {
    # Americas
    'US': '🌎 Americas', 'CA': '🌎 Americas', 'MX': '🌎 Americas', 'BR': '🌎 Americas',
    'AR': '🌎 Americas', 'CL': '🌎 Americas', 'CO': '🌎 Americas', 'PE': '🌎 Americas',
    # Europe
    'GB': '🌍 Europe', 'DE': '🌍 Europe', 'FR': '🌍 Europe', 'NL': '🌍 Europe',
    'BE': '🌍 Europe', 'IT': '🌍 Europe', 'ES': '🌍 Europe', 'PL': '🌍 Europe',
    'SE': '🌍 Europe', 'NO': '🌍 Europe', 'DK': '🌍 Europe', 'FI': '🌍 Europe',
    'AT': '🌍 Europe', 'CH': '🌍 Europe', 'IE': '🌍 Europe', 'PT': '🌍 Europe',
    'CZ': '🌍 Europe', 'RO': '🌍 Europe', 'HU': '🌍 Europe', 'UA': '🌍 Europe',
    'RU': '🌍 Europe',
    # Asia-Pacific
    'CN': '🌏 Asia', 'JP': '🌏 Asia', 'KR': '🌏 Asia', 'IN': '🌏 Asia',
    'SG': '🌏 Asia', 'HK': '🌏 Asia', 'TW': '🌏 Asia', 'AU': '🌏 Asia',
    'NZ': '🌏 Asia', 'ID': '🌏 Asia', 'TH': '🌏 Asia', 'VN': '🌏 Asia',
    'MY': '🌏 Asia', 'PH': '🌏 Asia',
}

# Default thresholds
DEFAULT_THRESHOLDS = {
    "util_warn": 70,
    "util_crit": 90,
    "resets_warn": 0.1,
    "resets_crit": 1.0,
    "ip_err_warn": 0.1,
    "ip_err_crit": 1.0,
    "icmp_err_warn": 0.1,
    "icmp_err_crit": 1.0,
    "if_err_warn": 0.1,
    "if_err_crit": 1.0,
    "tcp_fails_warn": 0.5,
    "tcp_fails_crit": 2.0,
    "tcp_retrans_warn": 1.0,
    "tcp_retrans_crit": 5.0
}