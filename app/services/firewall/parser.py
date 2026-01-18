import re
from typing import Optional, Dict, Any
from datetime import datetime

class FirewallEvent:
    """Normalized usage of firewall event."""
    def __init__(
        self,
        timestamp: datetime,
        action: Optional[str],
        interface: Optional[str],
        direction: Optional[str],
        protocol: Optional[str],
        src_ip: Optional[str],
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        rule_id: Optional[str],
        rule_label: Optional[str],
        reason: Optional[str]
    ):
        self.timestamp = timestamp
        self.action = action
        self.interface = interface
        self.direction = direction
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.rule_id = rule_id
        self.rule_label = rule_label
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        import time
        return {
            "timestamp": self.timestamp.isoformat(),
            "timestamp_ts": self.timestamp.timestamp(),
            "action": self.action,
            "interface": self.interface,
            "direction": self.direction,
            "proto": self.protocol,  # Map to proto for frontend compatibility
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "rule_id": self.rule_id,
            "rule_label": self.rule_label,
            "reason": self.reason
        }

    def __repr__(self):
        return f"<FirewallEvent {self.action} {self.src_ip}->{self.dst_ip} ({self.protocol})>"


class FirewallParser:
    """
    Dedicated parser for OPNsense firewall logs (RFC5424 / BSD filterlog).
    Also handles generic syslog messages for non-filterlog OPNsense applications.
    Scope: Ingestion + Normalization ONLY.
    Does NOT: Correlate, Metricize, or Alert.
    """

    # Pattern to extract program name from syslog (e.g., "configd[1234]:" or "openvpn:")
    # Matches program name that starts with a letter, followed by optional [pid], then colon
    SYSLOG_PROGRAM_PATTERN = re.compile(r'\s([a-zA-Z][a-zA-Z0-9_-]*)(?:\[\d+\])?:\s*(.*)$')

    # RFC5424 timestamp pattern
    RFC5424_TS_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)')

    def parse(self, raw_log: str) -> Optional[FirewallEvent]:
        """
        Parses a raw syslog line into a FirewallEvent.
        Handles both filterlog (packet filter) and generic syslog messages.
        """
        if 'filterlog' in raw_log:
            return self._parse_filterlog(raw_log)
        else:
            return self._parse_generic(raw_log)

    def _parse_generic(self, raw_log: str) -> Optional[FirewallEvent]:
        """
        Parse generic OPNsense syslog messages (non-filterlog).
        Extracts program name and message content.
        """
        try:
            # Try to extract timestamp from RFC5424 format
            timestamp = datetime.now()
            ts_match = self.RFC5424_TS_PATTERN.search(raw_log)
            if ts_match:
                try:
                    ts_str = ts_match.group(1)
                    # Handle timezone offset
                    if ts_str.endswith('Z'):
                        ts_str = ts_str[:-1] + '+00:00'
                    timestamp = datetime.fromisoformat(ts_str)
                except (ValueError, IndexError):
                    pass

            # Extract program name and message
            program = "syslog"
            message = raw_log

            # Try to find program name pattern
            prog_match = self.SYSLOG_PROGRAM_PATTERN.search(raw_log)
            if prog_match:
                program = prog_match.group(1)
                message = prog_match.group(2).strip()

            # Create a generic event with program as action and message as reason
            return FirewallEvent(
                timestamp=timestamp,
                action=program,  # Use program name as "action" for display
                interface=None,
                direction=None,
                protocol=None,
                src_ip=None,
                src_port=None,
                dst_ip=None,
                dst_port=None,
                rule_id=None,
                rule_label=None,
                reason=message[:500] if message else None  # Truncate long messages
            )
        except Exception:
            return None

    def _parse_filterlog(self, raw_log: str) -> Optional[FirewallEvent]:
        """
        Parses filterlog (packet filter) syslog lines.
        """

        try:
            # 1. basic syslog extraction (timestamp, message body)
            # Example: <134>1 2026-01-18T10:00:00.123456+00:00 OPNsense.localdomain filterlog 12345 - [meta sequenceId="1"] 56,0, ...
            # We assume the log part starts after 'filterlog' and brackets if present.
            
            # Simple split to find the CSV part
            # OPNsense/BSD filterlog CSV data usually starts closely after 'filterlog' preamble
            # We look for the first comma-separated sequence that starts with a number (rule id)
            
            # Use regex to strip syslog header
            # Matches: ... filterlog ... : <CSV>
            # Or: ... filterlog: <CSV>
            
            # Looking at typical OPNsense format in syslogs:
            # ... filterlog[pid]: rule,subrule,...
            
            parts = raw_log.split('filterlog', 1)
            if len(parts) < 2:
                return None
                
            csv_part = parts[1]
            # Strip PID if present: [12345]:
            csv_part = re.sub(r'^\[\d+\]:\s*', '', csv_part)
            # Strip preamble like ': '
            csv_part = csv_part.lstrip(': ').strip()
            
            # 2. Split CSV
            fields = csv_part.split(',')
            
            if len(fields) < 10:
                # Not enough fields for even a basic IPv4 packet
                return None

            # 3. Parse Fields based on position
            # Ref: https://docs.opnsense.org/manual/logging.html
            
            # 0: rule number
            # 1: sub rule number (not needed)
            # 2: anchor name (not needed)
            # 3: tracker id (rule label often mapped here or rule_id)
            # 4: interface
            # 5: reason
            # 6: action
            # 7: direction
            # 8: ip version
            
            rule_id = fields[0] if fields[0] and fields[0].isdigit() else None
            # Tracker is roughly equivalent to a stable rule ID or label key
            tracker = fields[3] if len(fields) > 3 else None
            
            interface = fields[4]
            reason = fields[5]
            action = fields[6]
            direction = fields[7]
            ip_ver = fields[8]

            # Nullable placeholders
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = None
            
            # IPv4 Processing
            if ip_ver == '4':
                # 9: tos, 10: ecn, 11: ttl, 12: id, 13: offset, 14: flags, 15: proto_id, 16: proto_text
                # IPv4 base fields length = 19 (up to dst_ip), then data length/payload
                
                if len(fields) < 20: 
                    return None
                    
                protocol = fields[16].lower()
                length = fields[17] # packet length
                src_ip = fields[18]
                dst_ip = fields[19]
                
                # Port parsing (TCP/UDP)
                # If proto is tcp(6) or udp(17), ports follow
                if protocol in ['tcp', 'udp', 'sctp'] and len(fields) >= 22:
                    src_port = int(fields[20])
                    dst_port = int(fields[21])
                    if len(fields) > 22:
                        # For TCP there might be data length afterwards
                        pass

            # IPv6 Processing
            elif ip_ver == '6':
                # 9: class, 10: flow label, 11: hop limit, 12: proto_text, 13: proto_id, 14: length, 15: src_ip, 16: dst_ip
                if len(fields) < 17:
                    return None
                    
                protocol = fields[12].lower()
                # fields[13] is numeric proto id
                # fields[14] is length
                src_ip = fields[15]
                dst_ip = fields[16]
                
                if protocol in ['tcp', 'udp', 'sctp'] and len(fields) >= 19:
                    src_port = int(fields[17])
                    dst_port = int(fields[18])

            else:
                # Non-IP or unknown version, we might skip or record as much as possible
                # But requirement says "Missing fields must remain null", so we proceed with what we have
                pass

            # Timestamp extraction from syslog header
            # We'll use "now" if parsing fails, but ideally we parse the syslog timestamp.
            # For this step, using current server time is often acceptable for real-time streams,
            # but let's try to grab a timestamp if flexible.
            # OPNsense format often includes ISO8601 or BSD format.
            timestamp = datetime.now()
            
            # Construct Event
            event = FirewallEvent(
                timestamp=timestamp,
                action=action,
                interface=interface,
                direction=direction,
                protocol=protocol,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                rule_id=rule_id,
                rule_label=tracker, # Using tracker as label/ID ref
                reason=reason
            )
            
            return event

        except Exception as e:
            # Parse error - return None (fail safe)
            # In debug mode one might print(e)
            return None
