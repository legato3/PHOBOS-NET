"""
Network Tools Service - DNS, Port Check, Ping, Reputation, Whois
"""
import subprocess
import socket
import ssl
import re
from datetime import datetime
from typing import Dict, List, Optional, Any

import logging
import requests

def dns_lookup(query: str, record_type: str = 'A') -> Dict[str, Any]:
    """Perform DNS lookup using dig command."""
    if not query:
        return {'error': 'Query is required'}
    
    # Sanitize input
    query = re.sub(r'[^a-zA-Z0-9.\-]', '', query)

    # Prevent Argument Injection
    if query.startswith('-'):
        return {'error': 'Invalid query format'}

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
    
    # Prevent Argument Injection
    if host.startswith('-'):
        return {'error': 'Invalid host format'}

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
    
    # Prevent Argument Injection
    if query.startswith('-'):
        return {'error': 'Invalid query format'}

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
    """Probe an HTTP endpoint for status, latency, and headers.
    
    Includes comprehensive SSRF guardrails to prevent internal/private network probing.
    Exposed via api_tools_http_probe route.
    """
    from app.services.shared.helpers import is_internal
    from urllib.parse import urlparse, urljoin

    if not url:
        return {'error': 'URL is required'}

    # Work with a stripped copy of the user-provided URL
    url = url.strip()
    
    # 1. Enforcement: Scheme validation (fail fast)
    if not re.match(r'^https?://', url, re.IGNORECASE):
        # Default to http if no scheme, but re-validate
        if '://' not in url:
            url = f'http://{url}'
        else:
            return {'error': 'Only http and https schemes are permitted'}

    try:
        def validate_target(target_url: str):
            parsed = urlparse(target_url)
            scheme = (parsed.scheme or '').lower()
            if scheme not in ['http', 'https']:
                return False, f"Invalid scheme: {parsed.scheme}"
            
            host = parsed.hostname
            if not host:
                return False, "Invalid URL: no hostname"
            
            # Check host for internal/forbidden patterns
            if is_internal(host):
                return False, "Access to restricted address is forbidden"
                
            # Resolve to all IPs (v4/v6) to prevent DNS rebinding
            try:
                # getaddrinfo returns a list of address info tuples
                addr_info = socket.getaddrinfo(
                    host,
                    parsed.port or (80 if scheme == 'http' else 443)
                )
                for info in addr_info:
                    ip = info[4][0]
                    if is_internal(ip):
                        return False, f"Restricted IP resolved: {ip}"
            except socket.gaierror:
                # Let requests handle final resolution if it survives initial checks
                pass
            
            return True, None

        # Initial validation on the normalized URL
        is_ok, err_msg = validate_target(url)
        if not is_ok:
            return {'error': f"SSRF Guard: {err_msg}"}
        # Use a separate variable to make it explicit that the URL has passed validation
        validated_url = url


        # Create a session with a custom adapter that refuses internal IPs at connect time
        class SafeHTTPAdapter(requests.adapters.HTTPAdapter):
            def get_connection(self, url, proxies=None):
                conn = super().get_connection(url, proxies=proxies)
                # Wrap the underlying connection pool's _new_conn to enforce IP checks
                if hasattr(conn, "pool") and hasattr(conn.pool, "_get_conn"):
                    orig_get_conn = conn.pool._get_conn

                    def _wrapped_get_conn(timeout=None):
                        c = orig_get_conn(timeout=timeout)
                        try:
                            host = getattr(c, "host", None)
                            port = getattr(c, "port", None)
                            if host:
                                try:
                                    # Resolve host to IP and apply internal check
                                    infos = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
                                    for family, _, _, _, sockaddr in infos:
                                        ip = sockaddr[0]
                                        if is_internal(ip):
                                            raise requests.exceptions.RequestException(
                                                f"Blocked internal IP address {ip}"
                                            )
                                except socket.gaierror:
                                    # If resolution fails, let the original error surface later
                                    pass
                        except Exception:
                            # Avoid breaking the adapter; any raised RequestException will be caught by caller
                            raise
                        return c

                    conn.pool._get_conn = _wrapped_get_conn
                return conn

        session = requests.Session()
        adapter = SafeHTTPAdapter()
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Custom redirect loop for SSRF protection
        max_redirects = 5
        redirect_chain = []
        current_url = validated_url
        max_bytes = 1024 * 1024 # 1MB limit for safety
        
        for _ in range(max_redirects + 1):
            # We use stream=True to prevent buffering the whole response in memory
            response = session.get(
                current_url,
                timeout=(3, 8),
                allow_redirects=False,  # Manual handling for safety
                headers={'User-Agent': 'PHOBOS-NET/1.0'},
                stream=True
            )
            
            # Record any redirects found in response history if they were allowed, 
            # though here we disable auto-redirects and handle manually.
            
            if response.is_redirect:
                location = response.headers.get('Location')
                if not location:
                    response.close()
                    break
                
                next_url = urljoin(current_url, location)
                
                # Re-validate redirect target
                is_ok, err_msg = validate_target(next_url)
                if not is_ok:
                    response.close()
                    return {'error': f"SSRF Guard (Redirect): {err_msg}"}
                
                redirect_chain.append({'status': response.status_code, 'url': current_url})
                response.close()  # Close current connection before redirecting
                current_url = next_url
            else:
                # Consume a small portion of the body (or just close if we only care about headers)
                # This protects against memory exhaustion if the response is a large file.
                try:
                    bytes_read = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        bytes_read += len(chunk)
                        if bytes_read > max_bytes:
                            break
                finally:
                    response.close()
                break
        else:
            return {'error': 'Too many redirects'}

        elapsed_ms = int(response.elapsed.total_seconds() * 1000)
        headers = {
            'content-type': response.headers.get('Content-Type', ''),
            'content-length': response.headers.get('Content-Length', ''),
            'server': response.headers.get('Server', ''),
            'cache-control': response.headers.get('Cache-Control', ''),
            'location': response.headers.get('Location', '')
        }
        return {
            'url': validated_url,
            'final_url': current_url,
            'status_code': response.status_code,
            'elapsed_ms': elapsed_ms,
            'redirect_chain': redirect_chain,
            'headers': {k: v for k, v in headers.items() if v}
        }
    except requests.exceptions.RequestException as e:
        # Log full exception details server-side, but return a generic error to the client
        logging.exception("HTTP probe failed for URL %s", url)
        return {'error': 'HTTP probe failed'}


def tls_inspect(host: str, port: str = '443') -> Dict[str, Any]:
    """Inspect TLS certificate details for a host.
    
    Includes SSRF guardrails to prevent internal/private network probing.
    Exposed via api_tools_tls_inspect route.
    """
    from app.services.shared.helpers import is_internal
    if not host:
        return {'error': 'Host is required'}

    host = host.strip()
    host = re.sub(r'[^a-zA-Z0-9.\-]', '', host)
    if not host:
        return {'error': 'Invalid host'}

    # 1. Host validation: SSRF protection
    if is_internal(host):
        return {'error': 'Access to restricted address is forbidden'}

    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return {'error': 'Port out of range'}
    except (TypeError, ValueError):
        return {'error': 'Invalid port'}

    try:
        # 2. Resolve IP(s) and check them all to prevent SSRF/Rebinding
        resolved_ip = None
        try:
            # getaddrinfo returns a list of address info tuples
            # We check all resolved addresses (v4/v6)
            addr_info = socket.getaddrinfo(host, port_num)
            for info in addr_info:
                ip = info[4][0]
                if is_internal(ip):
                    return {'error': f'Access to restricted IP is forbidden: {ip}'}
                if not resolved_ip:
                    resolved_ip = ip # Use first safe IP
        except socket.gaierror:
            return {'error': f'Could not resolve host: {host}'}

        if not resolved_ip:
            return {'error': 'No safe IP addresses found for host'}

        context = ssl.create_default_context()
        # Restrict to modern TLS versions (TLS 1.2+)
        try:
            # Prefer explicit minimum version when available (Python 3.7+)
            if hasattr(ssl, "TLSVersion") and hasattr(context, "minimum_version"):
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            # Fallback for older Python/OpenSSL: disable TLSv1 and TLSv1_1 if supported
            for opt_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
                opt = getattr(ssl, opt_name, None)
                if opt is not None:
                    context.options |= opt

        # Use a safe resolved IP for connection
        with socket.create_connection((resolved_ip, port_num), timeout=5) as sock:
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
        # Log detailed error server-side but return a generic message to the client
        logging.warning("TLS inspection connection error for %s:%s: %s", host, port, e)
        return {'error': 'TLS inspection failed due to a connection or TLS error'}
    except Exception as e:
        # Log full stack trace for unexpected errors while keeping the client message generic
        logging.error("TLS inspection unexpected error: %s", e)
        return {'error': 'TLS inspection failed'}
