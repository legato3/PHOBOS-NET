"""
Network Tools Service - DNS, Port Check, Ping, Reputation, Whois
"""
import subprocess
import socket
import ssl
import re
from datetime import datetime
from typing import Dict, List, Optional, Any

import requests

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


def http_probe(url: str) -> Dict[str, Any]:
    """Probe an HTTP endpoint for status, latency, and headers."""
    if not url:
        return {'error': 'URL is required'}

    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f'http://{url}'

    if not re.match(r'^https?://', url, re.IGNORECASE):
        return {'error': 'Invalid URL scheme'}

    try:
        response = requests.get(
            url,
            timeout=(3, 8),
            allow_redirects=True,
            headers={'User-Agent': 'PHOBOS-NET/1.0'}
        )
        elapsed_ms = int(response.elapsed.total_seconds() * 1000)
        redirects = [{'status': r.status_code, 'url': r.url} for r in response.history]
        headers = {
            'content-type': response.headers.get('Content-Type', ''),
            'content-length': response.headers.get('Content-Length', ''),
            'server': response.headers.get('Server', ''),
            'cache-control': response.headers.get('Cache-Control', ''),
            'location': response.headers.get('Location', '')
        }
        return {
            'url': url,
            'final_url': response.url,
            'status_code': response.status_code,
            'elapsed_ms': elapsed_ms,
            'redirect_chain': redirects,
            'headers': {k: v for k, v in headers.items() if v}
        }
    except requests.exceptions.RequestException as e:
        return {'error': f'HTTP probe failed: {str(e)}'}


def tls_inspect(host: str, port: str = '443') -> Dict[str, Any]:
    """Inspect TLS certificate details for a host."""
    if not host:
        return {'error': 'Host is required'}

    host = host.strip()
    host = re.sub(r'[^a-zA-Z0-9.\-]', '', host)
    if not host:
        return {'error': 'Invalid host'}

    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return {'error': 'Port out of range'}
    except (TypeError, ValueError):
        return {'error': 'Invalid port'}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port_num), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()

        subject_cn = ''
        issuer_cn = ''
        for item in cert.get('subject', []):
            for key, value in item:
                if key.lower() == 'commonname':
                    subject_cn = value
                    break
        for item in cert.get('issuer', []):
            for key, value in item:
                if key.lower() == 'commonname':
                    issuer_cn = value
                    break

        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        days_remaining = None
        if not_after:
            try:
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry - datetime.utcnow()).days
            except ValueError:
                days_remaining = None

        san = []
        for name_type, name in cert.get('subjectAltName', []):
            if name_type.lower() == 'dns':
                san.append(name)

        return {
            'host': host,
            'port': port_num,
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'not_before': not_before,
            'not_after': not_after,
            'days_remaining': days_remaining,
            'san': san,
            'tls_version': tls_version,
            'cipher': cipher[0] if cipher else None
        }
    except (socket.timeout, ConnectionError, ssl.SSLError) as e:
        return {'error': f'TLS inspection failed: {str(e)}'}
    except Exception as e:
        return {'error': f'TLS inspection failed: {str(e)}'}
