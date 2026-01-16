"""
Network Tools Service - DNS, Port Check, Ping, Reputation, Whois
"""
import subprocess
import socket
import re
from typing import Dict, List, Optional, Any


def dns_lookup(query: str, record_type: str = 'A') -> Dict[str, Any]:
    """Perform DNS lookup using dig command."""
    if not query:
        return {'error': 'Query is required'}
    
    # Sanitize input
    query = re.sub(r'[^a-zA-Z0-9.\-]', '', query)
    record_type = record_type.upper()
    
    if record_type not in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'PTR', 'CNAME', 'SOA']:
        record_type = 'A'
    
    try:
        result = subprocess.run(
            ['dig', '+short', query, record_type],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout.strip()
        if not output:
            output = f"No {record_type} records found for {query}"
        return {'result': output, 'query': query, 'type': record_type}
    except subprocess.TimeoutExpired:
        return {'error': 'DNS lookup timed out'}
    except Exception as e:
        return {'error': f'DNS lookup failed: {str(e)}'}


def port_check(host: str, ports: str) -> Dict[str, Any]:
    """Check if ports are open on a host."""
    if not host or not ports:
        return {'error': 'Host and ports are required'}
    
    # Sanitize host
    host = re.sub(r'[^a-zA-Z0-9.\-]', '', host)
    
    # Parse ports
    port_list = []
    for p in ports.split(','):
        p = p.strip()
        if p.isdigit():
            port_num = int(p)
            if 1 <= port_num <= 65535:
                port_list.append(port_num)
    
    if not port_list:
        return {'error': 'No valid ports specified'}
    
    if len(port_list) > 20:
        return {'error': 'Maximum 20 ports allowed'}
    
    # Common port services
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    
    results = []
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            is_open = result == 0
            sock.close()
            results.append({
                'port': port,
                'open': is_open,
                'service': services.get(port, '')
            })
        except Exception:
            results.append({
                'port': port,
                'open': False,
                'service': services.get(port, ''),
                'error': 'Connection failed'
            })
    
    return {'results': results, 'host': host}


def ping_host(host: str, mode: str = 'ping') -> Dict[str, Any]:
    """Ping or traceroute to a host."""
    if not host:
        return {'error': 'Host is required'}
    
    # Sanitize host
    host = re.sub(r'[^a-zA-Z0-9.\-]', '', host)
    
    if not host:
        return {'error': 'Invalid host'}
    
    try:
        if mode == 'traceroute':
            # Try traceroute first, fall back to tracepath
            try:
                result = subprocess.run(
                    ['traceroute', '-m', '15', '-w', '2', host],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            except FileNotFoundError:
                # Try tracepath as fallback
                result = subprocess.run(
                    ['tracepath', host],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
        else:
            # Ping with count and timeout
            result = subprocess.run(
                ['ping', '-c', '4', '-w', '5', host],
                capture_output=True,
                text=True,
                timeout=15
            )
        
        output = result.stdout.strip()
        if not output and result.stderr:
            output = result.stderr.strip()
        if not output:
            output = f"No response from {host}"
        
        return {'result': output, 'host': host, 'mode': mode}
    except subprocess.TimeoutExpired:
        return {'error': f'{mode.capitalize()} timed out'}
    except FileNotFoundError:
        return {'error': f'{mode} command not found'}
    except Exception as e:
        return {'error': f'{mode.capitalize()} failed: {str(e)}'}


def check_reputation(ip: str, threat_feeds: Optional[set] = None) -> Dict[str, Any]:
    """Check IP against loaded threat feeds."""
    if not ip:
        return {'error': 'IP address is required'}
    
    # Validate IP format
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return {'error': 'Invalid IP address format'}
    
    # Check against threat feeds if provided
    is_threat = False
    matched_feeds = []
    category = 'Unknown'
    
    if threat_feeds and ip in threat_feeds:
        is_threat = True
        matched_feeds = ['Local Threat Feed']
        category = 'Malicious'
    
    return {
        'ip': ip,
        'is_threat': is_threat,
        'feeds': matched_feeds if matched_feeds else None,
        'category': category if is_threat else 'Clean',
        'last_seen': None
    }


def whois_lookup(query: str) -> Dict[str, Any]:
    """Perform basic whois/ASN lookup."""
    if not query:
        return {'error': 'Query is required'}
    
    # Sanitize input
    query = re.sub(r'[^a-zA-Z0-9.\-]', '', query)
    
    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = bool(re.match(ip_pattern, query))
    
    try:
        if is_ip:
            # Use whois for IP
            result = subprocess.run(
                ['whois', query],
                capture_output=True,
                text=True,
                timeout=15
            )
            output = result.stdout
            
            # Parse common fields
            asn = None
            org = None
            country = None
            network = None
            
            for line in output.split('\n'):
                line_lower = line.lower()
                if 'origin' in line_lower and not asn:
                    match = re.search(r'AS\d+', line, re.IGNORECASE)
                    if match:
                        asn = match.group(0)
                elif 'orgname' in line_lower or 'org-name' in line_lower:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        org = parts[1].strip()
                elif 'country' in line_lower and not country:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        country = parts[1].strip()[:2].upper()
                elif 'cidr' in line_lower or 'inetnum' in line_lower:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        network = parts[1].strip()
            
            return {
                'query': query,
                'asn': asn,
                'org': org,
                'country': country,
                'network': network
            }
        else:
            # Domain whois
            result = subprocess.run(
                ['whois', query],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            # Just return basic info
            return {
                'query': query,
                'asn': None,
                'org': 'See full whois',
                'country': None,
                'network': None
            }
    except subprocess.TimeoutExpired:
        return {'error': 'Whois lookup timed out'}
    except FileNotFoundError:
        return {'error': 'whois command not found'}
    except Exception as e:
        return {'error': f'Whois lookup failed: {str(e)}'}
