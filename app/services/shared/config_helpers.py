"""Configuration helper functions for loading and saving configuration files."""
import os
import json
import app.config as app_config
import app.services.shared.dns as dns_module
from app.config import NOTIFY_CFG_PATH, THRESHOLDS_CFG_PATH, CONFIG_PATH, DEFAULT_THRESHOLDS


def load_notify_cfg():
    """Load notification configuration from file or return defaults."""
    default = {"email": True, "webhook": True, "mute_until": 0}
    if not os.path.exists(NOTIFY_CFG_PATH):
        return default
    try:
        with open(NOTIFY_CFG_PATH, 'r') as f:
            cfg = json.load(f)
        return {
            "email": bool(cfg.get("email", True)),
            "webhook": bool(cfg.get("webhook", True)),
            "mute_until": float(cfg.get("mute_until", 0) or 0)
        }
    except Exception:
        return default


def save_notify_cfg(cfg):
    """Save notification configuration to file."""
    try:
        payload = {
            "email": bool(cfg.get('email', True)),
            "webhook": bool(cfg.get('webhook', True)),
            "mute_until": float(cfg.get('mute_until', 0) or 0)
        }
        with open(NOTIFY_CFG_PATH, 'w') as f:
            json.dump(payload, f)
    except Exception:
        pass


def load_thresholds():
    """Load thresholds configuration from file or return defaults."""
    data = DEFAULT_THRESHOLDS.copy()
    if os.path.exists(THRESHOLDS_CFG_PATH):
        try:
            with open(THRESHOLDS_CFG_PATH, 'r') as f:
                file_cfg = json.load(f)
                for k, v in file_cfg.items():
                    try:
                        # Cast to float for rates, int for util
                        if k.startswith('util_'):
                            data[k] = int(v)
                        else:
                            data[k] = float(v)
                    except Exception:
                        pass
        except Exception:
            pass
    return data


def save_thresholds(cfg):
    """Save thresholds configuration to file."""
    try:
        data = load_thresholds()
        for k in DEFAULT_THRESHOLDS.keys():
            if k in cfg:
                try:
                    if k.startswith('util_'):
                        data[k] = int(cfg[k])
                    else:
                        data[k] = float(cfg[k])
                except Exception:
                    pass
        with open(THRESHOLDS_CFG_PATH, 'w') as f:
            json.dump(data, f, indent=2)
        return data
    except Exception:
        return load_thresholds()


def get_default_config():
    """Return default configuration values."""
    return {
        'dns_server': '192.168.0.6',
        'snmp_host': '192.168.0.1',
        'snmp_community': 'public',
        'snmp_poll_interval': 2.0,
        'nfdump_dir': '/var/cache/nfdump',
        'geoip_city_path': '/root/GeoLite2-City.mmdb',
        'geoip_asn_path': '/root/GeoLite2-ASN.mmdb',
        'threat_feeds_path': '/root/threat-feeds.txt',
        'internal_networks': '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12'
    }


def load_config():
    """Load configuration from file or return defaults."""
    defaults = get_default_config()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                saved = json.load(f)
                # Merge with defaults (saved values override)
                return {**defaults, **saved}
        except Exception:
            pass
    return defaults


def save_config(data):
    """Save configuration to file."""
    current = load_config()
    # Only allow specific keys to be saved
    allowed_keys = get_default_config().keys()
    for k in allowed_keys:
        if k in data:
            current[k] = data[k]
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(current, f, indent=2)
        # Apply runtime updates where possible
        if 'dns_server' in data and data['dns_server']:
            dns_server = data['dns_server']
            app_config.DNS_SERVER = dns_server
            dns_module.DNS_SERVER = dns_server
            dns_module._shared_resolver.nameservers = [dns_server]
        if 'snmp_host' in data:
            app_config.SNMP_HOST = data['snmp_host']
            try:
                import app.services.shared.snmp as snmp_module
                snmp_module.SNMP_HOST = data['snmp_host']
            except Exception:
                pass
        if 'snmp_community' in data:
            app_config.SNMP_COMMUNITY = data['snmp_community']
            try:
                import app.services.shared.snmp as snmp_module
                snmp_module.SNMP_COMMUNITY = data['snmp_community']
            except Exception:
                pass
        if 'snmp_poll_interval' in data:
            poll_interval = float(data['snmp_poll_interval'])
            app_config.SNMP_POLL_INTERVAL = poll_interval
            try:
                import app.services.shared.snmp as snmp_module
                snmp_module.SNMP_POLL_INTERVAL = poll_interval
            except Exception:
                pass
    except Exception as e:
        print(f"Error saving config: {e}")
    return current
