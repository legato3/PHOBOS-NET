import subprocess
import json
import logging
import shutil
import re
from datetime import datetime

logger = logging.getLogger(__name__)

def get_local_subnets():
    """
    Detect local subnets using 'ip -j addr'.
    Returns a list of dicts: {'interface': 'eth0', 'cidr': '192.168.1.0/24', 'ip': '192.168.1.10'}
    """
    if not shutil.which("ip"):
        logger.error("ip command not found")
        return []

    try:
        output = subprocess.check_output(["ip", "-j", "addr"], timeout=5).decode("utf-8")
        interfaces = json.loads(output)
        
        subnets = []
        for iface in interfaces:
            if iface.get("ifname") == "lo":
                continue
            
            for addr_info in iface.get("addr_info", []):
                if addr_info.get("family") == "inet":
                    local = addr_info.get("local")
                    prefix = addr_info.get("prefixlen")
                    if local and prefix:
                        # Calculate network address using ipaddress for correctness
                        import ipaddress
                        try:
                            net = ipaddress.IPv4Interface(f"{local}/{prefix}").network
                            cidr = str(net)
                            subnets.append({
                                "interface": iface.get("ifname"),
                                "ip": local,
                                "cidr": cidr
                            })
                        except ValueError:
                             pass

        # Explicitly add 192.168.0.0/24 if not present (Common local subnet requested by user)
        # This handles the case where the container is bridge-networked but we want to scan the host lan
        found_common = any(s['cidr'] == '192.168.0.0/24' for s in subnets)
        if not found_common:
            subnets.append({
                "interface": "host-network", 
                "ip": "0.0.0.0", 
                "cidr": "192.168.0.0/24"
            })
            
        return subnets
    except Exception as e:
        logger.error(f"Failed to detect subnets: {e}")
        return []

def scan_network(target):
    """
    Perform an active ARP/Ping scan on the target CIDR/IP using nmap.
    Returns a list of discovered hosts.
    
    Args:
        target (str): CIDR or IP to scan (e.g., '192.168.1.0/24')
    """
    if not shutil.which("nmap"):
        logger.error("nmap not found")
        return {"error": "Scanner tool missing (nmap)"}

    # Validate target is safe (simple char check)
    if not re.match(r'^[0-9./]+$', target):
        return {"error": "Invalid target format"}

    logger.info(f"Starting active scan on {target}")
    
    # -sn: Ping Scan - disable port scan
    # -PR: ARP Ping (if local)
    # -PE: ICMP Echo (if remote)
    # -oX -: Output XML to stdout
    # Removed -n to allow DNS resolution
    cmd = ["nmap", "-sn", "-oX", "-", target]
    
    # If running as root (which we are in Docker), nmap automatically uses ARP for local subnets.
    
    try:
        xml_output = subprocess.check_output(cmd, timeout=120).decode("utf-8") # Increased timeout for DNS
        return parse_nmap_xml(xml_output)
    except subprocess.TimeoutExpired:
        logger.error("Scan timed out")
        return {"error": "Scan timed out"}
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return {"error": str(e)}

def parse_nmap_xml(xml_content):
    """
    Parse Nmap XML output to extract host info.
    We'll use simple string parsing or xml.etree to avoid heavy dependencies if possible.
    """
    import xml.etree.ElementTree as ET
    
    hosts = []
    try:
        root = ET.fromstring(xml_content)
        
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
                
            ip = None
            mac = None
            vendor = None
            hostname = None
            
            # Parse Addresses
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip = addr.get("addr")
                elif addr_type == "mac":
                    mac = addr.get("addr")
                    vendor = addr.get("vendor")

            # Parse Hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hn in hostnames.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostname = name
                        break # Take the first one
            
            if ip:
                hosts.append({
                    "ip": ip,
                    "mac": mac or "Unknown",
                    "vendor": vendor or "Unknown",
                    "hostname": hostname or "N/A",
                    "status": "Online",
                    "last_seen": datetime.now().isoformat()
                })
                
        return {"hosts": hosts, "count": len(hosts), "scanned_at": datetime.now().isoformat()}
        
    except Exception as e:
        logger.error(f"Failed to parse nmap XML: {e}")
        return {"error": "Failed to parse scan results"}
