"""Syslog services package."""
from app.services.syslog.firewall_listener import start_firewall_syslog_thread

__all__ = ['start_firewall_syslog_thread']
