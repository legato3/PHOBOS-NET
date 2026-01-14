"""Configuration helper functions for loading and saving configuration files."""
import os
import json
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
