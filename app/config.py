"""Configuration module for PROX_NFDUMP application."""
import os

# Cache TTLs
CACHE_TTL_SHORT = 30        # 30 seconds for fast-changing data
CACHE_TTL_THREAT = 900      # 15 minutes for threat feeds
DEFAULT_TIMEOUT = 25        # subprocess timeout
MAX_RESULTS = 100           # default limit for API results
DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

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