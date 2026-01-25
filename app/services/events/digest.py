import json
import os
import time
import smtplib
from email.message import EmailMessage
from typing import Dict, List, Optional

import requests

from app.config import (
    DIGEST_ENABLED,
    DIGEST_WEBHOOK_URL,
    DIGEST_EMAIL_TO,
    DIGEST_INTERVAL,
    SMTP_CFG_PATH,
)
from app.services.events.store import fetch_events


_STATE_PATH = "/dev/shm/phobos_digest.json"


def _load_state() -> Dict[str, float]:
    if os.path.exists(_STATE_PATH):
        try:
            with open(_STATE_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_state(state: Dict[str, float]) -> None:
    try:
        tmp = f"{_STATE_PATH}.tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, _STATE_PATH)
    except Exception:
        pass


def _interval_seconds() -> int:
    return 86400 if DIGEST_INTERVAL == "daily" else 3600


def _format_summary(events: List[Dict[str, object]]) -> str:
    if not events:
        return "No notable events in this interval."
    lines = []
    lines.append(f"Notable events ({DIGEST_INTERVAL}): {len(events)} total")
    lines.append("")
    for event in events[:5]:
        title = event.get("title") or "Event"
        source = event.get("source") or "system"
        summary = event.get("summary") or ""
        lines.append(f"- [{source}] {title} — {summary}")
    return "\n".join(lines)


def _load_smtp_cfg() -> Optional[Dict[str, object]]:
    if not os.path.exists(SMTP_CFG_PATH):
        return None
    try:
        with open(SMTP_CFG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _send_email(body: str) -> None:
    cfg = _load_smtp_cfg()
    if not cfg or not DIGEST_EMAIL_TO:
        return
    host = cfg.get("host")
    port = int(cfg.get("port", 25))
    username = cfg.get("username")
    password = cfg.get("password")
    sender = cfg.get("from") or username
    if not host or not sender:
        return

    msg = EmailMessage()
    msg["Subject"] = f"PHOBOS-NET digest ({DIGEST_INTERVAL})"
    msg["From"] = sender
    msg["To"] = DIGEST_EMAIL_TO
    msg.set_content(body)

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def _send_webhook(events: List[Dict[str, object]], body: str) -> None:
    if not DIGEST_WEBHOOK_URL:
        return
    payload = {
        "interval": DIGEST_INTERVAL,
        "total": len(events),
        "top": events[:5],
        "summary": body,
    }
    try:
        requests.post(DIGEST_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass


def run_digest_once() -> None:
    if not DIGEST_ENABLED:
        return
    interval_sec = _interval_seconds()
    now = time.time()
    state = _load_state()
    last_sent = float(state.get(DIGEST_INTERVAL, 0))
    if now - last_sent < interval_sec:
        return

    events = fetch_events("notable", range_sec=interval_sec, limit=200)
    if not events:
        return

    summary = _format_summary(events)
    _send_webhook(events, summary)
    _send_email(summary)

    state[DIGEST_INTERVAL] = now
    _save_state(state)
