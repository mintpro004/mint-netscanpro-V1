#!/usr/bin/env python3
"""
NetScan Pro - Real Network Scanner Backend
Supports: Linux, macOS, Windows, Debian, Ubuntu, ChromeOS
"""

import asyncio
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

# Global lock for thread-safe access to scan_state
state_lock = threading.Lock()

# Optional imports - gracefully handled
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("netscan")

OS = platform.system()  # 'Linux', 'Darwin', 'Windows'

# ─────────────────────────────────────────────────────────────
# NETWORK UTILITIES
# ─────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_network_interfaces():
    interfaces = []
    if HAS_NETIFACES:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get('addr', '')
                    mask = addr.get('netmask', '255.255.255.0')
                    if ip and not ip.startswith('127.'):
                        interfaces.append({
                            "name": iface,
                            "ip": ip,
                            "netmask": mask,
                            "cidr": ip_to_cidr(ip, mask)
                        })
    elif HAS_PSUTIL:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    interfaces.append({
                        "name": iface,
                        "ip": addr.address,
                        "netmask": addr.netmask or "255.255.255.0",
                        "cidr": ip_to_cidr(addr.address, addr.netmask or "255.255.255.0")
                    })
    else:
        ip = get_local_ip()
        interfaces.append({"name": "default", "ip": ip, "netmask": "255.255.255.0", "cidr": f"{ip}/24"})
    return interfaces

def ip_to_cidr(ip, mask):
    try:
        parts = mask.split('.')
        bits = sum(bin(int(p)).count('1') for p in parts)
        net = ".".join(str(int(a) & int(b)) for a, b in zip(ip.split('.'), mask.split('.')))
        return f"{net}/{bits}"
    except Exception:
        return f"{ip}/24"

def get_mac_for_ip(ip):
    """Get MAC address from ARP table or via ARP ping"""
    if HAS_SCAPY:
        try:
            # Send ARP request
            ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=1, verbose=False)
            for snd, rcv in ans:
                return rcv.hwsrc.upper()
        except Exception:
            pass

    try:
        if OS == 'Windows':
            out = subprocess.check_output(['arp', '-a', ip], timeout=3, stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    for p in parts:
                        if '-' in p and len(p) == 17:
                            return p.upper()
        else:
            out = subprocess.check_output(['arp', '-n', ip], timeout=3, stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                match = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', line)
                if match:
                    return match.group(0).upper()
    except Exception:
        pass

    # Try /proc/net/arp on Linux
    try:
        with open('/proc/net/arp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts[0] == ip and parts[3] != '00:00:00:00:00:00':
                    return parts[3].upper()
    except Exception:
        pass

    return "Unknown"

def get_vendor_from_mac(mac):
    """OUI lookup from first 3 octets"""
    OUI = {
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "00:1A:4B": "HP",
        "3C:22:FB": "Apple",
        "BE:D0:74": "Apple",
        "70:EC:E4": "Apple",
        "F4:F5:D8": "Google",
        "EC:B5:FA": "Philips",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "F8:04:2E": "Samsung",
        "FC:A1:83": "Amazon",
        "C4:9D:ED": "Microsoft",
        "00:11:32": "Synology",
        "14:CB:19": "Dell",
        "A4:C3:F0": "ASUS",
        "18:31:BF": "ASUS",
        "AC:22:0B": "TP-Link",
        "50:C7:BF": "TP-Link",
        "00:0C:29": "VMware",
        "00:1B:63": "Apple",
        "00:17:F2": "Apple",
        "40:6C:8F": "Apple",
        "00:E0:4C": "Realtek",
        "00:26:B9": "Dell",
        "B8:AC:6F": "Dell",
        "28:6C:07": "Dell",
    }
    prefix = mac[:8].upper() if mac and len(mac) >= 8 else ""
    return OUI.get(prefix, "Unknown")

def ping_host(ip, timeout=1):
    """Cross-platform ping returning (alive, latency_ms)"""
    try:
        if OS == 'Windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
        start = time.time()
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        elapsed = (time.time() - start) * 1000
        if result.returncode == 0:
            # Try to extract real RTT
            out = result.stdout.decode(errors='ignore')
            m = re.search(r'time[=<](\d+\.?\d*)', out)
            rtt = float(m.group(1)) if m else round(elapsed, 1)
            return True, round(rtt, 1)
    except Exception:
        pass
    return False, None

def scan_port(ip, port, timeout=0.5):
    """TCP connect scan on a single port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 548, 631, 873, 993, 995, 1080, 1433, 1521,
    2049, 3000, 3306, 3389, 5000, 5001, 5432, 5900, 6379,
    7000, 7070, 8000, 8008, 8009, 8080, 8443, 8888,
    9100, 9197, 27017
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 548: "AFP", 631: "IPP",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3000: "Node.js",
    3306: "MySQL", 3389: "RDP", 5000: "Dev/UPnP", 5001: "Synology HTTPS",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 7000: "AirPlay",
    7070: "RTSP", 8000: "HTTP-alt", 8008: "Chromecast", 8009: "Chromecast TLS",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "Jupyter",
    9100: "Raw print", 9197: "Samsung TV", 27017: "MongoDB"
}

def grab_banner(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in [80, 8080, 8000, 8008]:
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 22:
            pass  # SSH sends banner immediately
        data = s.recv(256)
        s.close()
        banner = data.decode(errors='ignore').strip().split('\n')[0][:80]
        return banner
    except Exception:
        return ""

def detect_os_ttl(ip):
    """Rough OS detection from ping TTL"""
    try:
        if OS == 'Windows':
            out = subprocess.check_output(['ping', '-n', '1', ip], timeout=3, stderr=subprocess.DEVNULL).decode()
        else:
            out = subprocess.check_output(['ping', '-c', '1', ip], timeout=3, stderr=subprocess.DEVNULL).decode()
        m = re.search(r'ttl[=: ]+(\d+)', out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64: return "Linux/Unix/Android/iOS"
            if ttl <= 128: return "Windows"
            if ttl <= 255: return "Network device"
    except Exception:
        pass
    return "Unknown"

# ─────────────────────────────────────────────────────────────
# DEVICE DISCOVERY
# ─────────────────────────────────────────────────────────────

def scan_network(cidr, progress_cb=None):
    """Discover all live hosts on the network"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
    except Exception:
        return []

    # Limit to /22 for performance (1024 hosts)
    if len(hosts) > 1024:
        log.warning(f"Network {cidr} is too large, limiting to first 1024 hosts")
        hosts = hosts[:1024]

    live = []
    scanned = 0
    total = len(hosts)

    def check(ip_obj):
        nonlocal scanned
        ip = str(ip_obj)
        alive, latency = ping_host(ip)
        scanned += 1
        if progress_cb:
            progress_cb(scanned, total, ip)
        if alive:
            return ip, latency
        return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(check, hosts))

    for r in results:
        if r:
            ip, latency = r
            mac = get_mac_for_ip(ip)
            vendor = get_vendor_from_mac(mac)
            os_guess = detect_os_ttl(ip)
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            name = hostname or vendor or ip
            dtype = classify_device(vendor, hostname, [])
            live.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "name": name,
                "type": dtype,
                "latency": latency,
                "os": os_guess,
                "status": "online",
                "ports": [],
                "uptime": "",
                "last_seen": datetime.now().isoformat()
            })

    return live

def classify_device(vendor, hostname, ports):
    v = (vendor + hostname).lower()
    if any(x in v for x in ['router', 'gateway', 'asus', 'netgear', 'ubiquiti', 'mikrotik', 'openwrt', 'dd-wrt', 'tp-link', 'linksys', 'd-link', 'cisco']):
        return "router"
    if any(x in v for x in ['iphone', 'ipad', 'android', 'samsung', 'pixel', 'oneplus']):
        return "phone"
    if any(x in v for x in ['macbook', 'macmini', 'imac', 'thinkpad', 'laptop', 'notebook']):
        return "laptop"
    if any(x in v for x in ['raspberry', 'pi', 'nas', 'synology', 'qnap', 'server', 'ubuntu', 'debian']):
        return "server"
    if any(x in v for x in ['printer', 'hp', 'canon', 'epson', 'brother', 'laserjet', 'inkjet']):
        return "printer"
    if any(x in v for x in ['chromecast', 'nest', 'echo', 'hue', 'smartthings', 'philips', 'google home', 'amazon']):
        return "iot"
    if any(x in v for x in ['xbox', 'playstation', 'nintendo', 'steam']):
        return "gaming"
    if any(x in v for x in ['samsung tv', 'lg tv', 'sony tv', 'vizio', 'roku', 'firetv', 'appletv']):
        return "tv"
    if 3389 in ports:
        return "desktop"
    return "unknown"

# ─────────────────────────────────────────────────────────────
# PORT SCANNER
# ─────────────────────────────────────────────────────────────

def full_port_scan(ip, port_list=None, progress_cb=None):
    if port_list is None:
        port_list = COMMON_PORTS
    results = []
    scanned = 0

    def check_port(port):
        nonlocal scanned
        open_ = scan_port(ip, port)
        scanned += 1
        if progress_cb:
            progress_cb(scanned, len(port_list), port)
        if open_:
            banner = grab_banner(ip, port)
            return {
                "port": port,
                "protocol": "TCP",
                "service": PORT_SERVICES.get(port, "Unknown"),
                "state": "open",
                "banner": banner
            }
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for r in ex.map(check_port, port_list):
            if r:
                results.append(r)

    return sorted(results, key=lambda x: x['port'])

# ─────────────────────────────────────────────────────────────
# VULNERABILITY ANALYSIS
# ─────────────────────────────────────────────────────────────

VULN_RULES = [
    {
        "id": "TELNET_OPEN",
        "check": lambda d: 23 in d.get("ports", []),
        "severity": "high",
        "title": "Telnet enabled",
        "desc": "Telnet transmits data in plaintext. Disable it and use SSH instead.",
        "cve": "CVE-2011-4862"
    },
    {
        "id": "SMB_OPEN",
        "check": lambda d: 445 in d.get("ports", []) and "Windows" in d.get("os", ""),
        "severity": "high",
        "title": "SMB port exposed",
        "desc": "SMB on Windows can be vulnerable to EternalBlue/WannaCry. Ensure patched and firewalled.",
        "cve": "CVE-2017-0144"
    },
    {
        "id": "RDP_EXPOSED",
        "check": lambda d: 3389 in d.get("ports", []),
        "severity": "high",
        "title": "RDP exposed to LAN",
        "desc": "Remote Desktop exposed. Enable NLA and use a VPN. Vulnerable to BlueKeep.",
        "cve": "CVE-2019-0708"
    },
    {
        "id": "HTTP_NO_TLS",
        "check": lambda d: 80 in d.get("ports", []) and 443 not in d.get("ports", []),
        "severity": "medium",
        "title": "HTTP without HTTPS",
        "desc": "Device serves HTTP without TLS. Traffic is unencrypted on your LAN.",
        "cve": ""
    },
    {
        "id": "VNC_OPEN",
        "check": lambda d: 5900 in d.get("ports", []),
        "severity": "high",
        "title": "VNC remote access open",
        "desc": "VNC is accessible. Ensure strong password. Consider tunneling over SSH.",
        "cve": ""
    },
    {
        "id": "MONGODB_EXPOSED",
        "check": lambda d: 27017 in d.get("ports", []),
        "severity": "high",
        "title": "MongoDB port exposed",
        "desc": "MongoDB accessible on LAN without auth by default. Restrict access immediately.",
        "cve": "CVE-2019-2389"
    },
    {
        "id": "REDIS_EXPOSED",
        "check": lambda d: 6379 in d.get("ports", []),
        "severity": "high",
        "title": "Redis port exposed",
        "desc": "Redis has no auth by default. Bind to 127.0.0.1 or set requirepass.",
        "cve": ""
    },
    {
        "id": "DB_EXPOSED",
        "check": lambda d: any(p in d.get("ports", []) for p in [5432, 3306, 1433, 1521]),
        "severity": "medium",
        "title": "Database port exposed on LAN",
        "desc": "Database accessible on LAN. Use firewall rules to restrict access.",
        "cve": ""
    },
    {
        "id": "NETBIOS",
        "check": lambda d: 139 in d.get("ports", []),
        "severity": "medium",
        "title": "NetBIOS/legacy SMB",
        "desc": "NetBIOS (port 139) is legacy and should be disabled on modern systems.",
        "cve": ""
    },
    {
        "id": "UPNP",
        "check": lambda d: 5000 in d.get("ports", []) and "router" in d.get("type", ""),
        "severity": "medium",
        "title": "UPnP possibly enabled",
        "desc": "UPnP allows devices to punch holes through your firewall. Disable if not needed.",
        "cve": "CVE-2013-0229"
    },
    {
        "id": "PRINT_RAW",
        "check": lambda d: 9100 in d.get("ports", []),
        "severity": "low",
        "title": "Raw print port open",
        "desc": "Port 9100 allows raw printing. Ensure printer access is restricted to trusted hosts.",
        "cve": ""
    },
]

def analyze_vulnerabilities(devices):
    findings = []
    for device in devices:
        for rule in VULN_RULES:
            try:
                if rule["check"](device):
                    findings.append({
                        "device_ip": device["ip"],
                        "device_name": device["name"],
                        "severity": rule["severity"],
                        "title": rule["title"],
                        "desc": rule["desc"],
                        "cve": rule["cve"],
                        "id": rule["id"]
                    })
            except Exception:
                pass
    return findings

# ─────────────────────────────────────────────────────────────
# SPEED TEST (real latency, upload/download via HTTP)
# ─────────────────────────────────────────────────────────────

def measure_ping(host="1.1.1.1"):
    alive, latency = ping_host(host, timeout=2)
    return latency

def measure_download_speed():
    """Download a test file and measure throughput"""
    import urllib.request
    url = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10MB
    try:
        start = time.time()
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = resp.read()
        elapsed = time.time() - start
        mbps = round((len(data) * 8) / (elapsed * 1_000_000), 2)
        return mbps
    except Exception:
        return None

def measure_upload_speed():
    """Upload test data and measure throughput"""
    import urllib.request
    url = "https://speed.cloudflare.com/__up"
    try:
        data = os.urandom(2_000_000)  # 2MB
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/octet-stream')
        start = time.time()
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        elapsed = time.time() - start
        mbps = round((len(data) * 8) / (elapsed * 1_000_000), 2)
        return mbps
    except Exception:
        return None

def run_speed_test(progress_cb=None):
    result = {}
    if progress_cb: progress_cb("Measuring ping...")
    result['ping'] = measure_ping()

    if progress_cb: progress_cb("Measuring download speed...")
    result['download'] = measure_download_speed()

    if progress_cb: progress_cb("Measuring upload speed...")
    result['upload'] = measure_upload_speed()

    result['timestamp'] = datetime.now().isoformat()
    return result

# ─────────────────────────────────────────────────────────────
# WI-FI SCANNER
# ─────────────────────────────────────────────────────────────

def scan_wifi():
    networks = []
    try:
        if OS == 'Linux':
            ifaces = [i for i in os.listdir('/sys/class/net') if i.startswith('w')]
            for iface in ifaces:
                try:
                    out = subprocess.check_output(
                        ['nmcli', '-t', '-f', 'SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY', 'dev', 'wifi', 'list'],
                        timeout=10, stderr=subprocess.DEVNULL
                    ).decode()
                    for line in out.strip().split('\n'):
                        parts = line.split(':')
                        if len(parts) >= 8:
                            try:
                                networks.append({
                                    "ssid": parts[0] or "Hidden",
                                    "bssid": parts[1],
                                    "mode": parts[2],
                                    "channel": int(parts[3]) if parts[3].isdigit() else 0,
                                    "frequency": parts[4],
                                    "rate": parts[5],
                                    "signal": int(parts[6]) if parts[6].lstrip('-').isdigit() else -100,
                                    "security": parts[7] if len(parts) > 7 else "Open",
                                    "band": "5GHz" if int(parts[3] or 0) > 14 else "2.4GHz"
                                })
                            except Exception:
                                pass
                    break
                except Exception:
                    pass

        elif OS == 'Darwin':
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport):
                out = subprocess.check_output([airport, '-s'], timeout=10).decode()
                for line in out.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 7:
                        try:
                            networks.append({
                                "ssid": parts[0],
                                "bssid": parts[1],
                                "signal": int(parts[2]),
                                "channel": int(parts[3].split(',')[0]),
                                "security": parts[6] if len(parts) > 6 else "WPA2",
                                "band": "5GHz" if int(parts[3].split(',')[0]) > 14 else "2.4GHz",
                                "frequency": "",
                                "rate": ""
                            })
                        except Exception:
                            pass

        elif OS == 'Windows':
            out = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                timeout=10, stderr=subprocess.DEVNULL
            ).decode()
            # Parse netsh output
            current = {}
            for line in out.split('\n'):
                line = line.strip()
                if line.startswith('SSID') and ':' in line and 'BSSID' not in line:
                    if current.get('ssid'): networks.append(current)
                    current = {'ssid': line.split(':', 1)[1].strip(), 'signal': -70, 'channel': 0, 'security': 'WPA2', 'band': '2.4GHz', 'bssid': '', 'frequency': '', 'rate': ''}
                elif 'Signal' in line and ':' in line:
                    try: current['signal'] = int(line.split(':')[1].strip().replace('%','')) - 100
                    except: pass
                elif 'Channel' in line and ':' in line:
                    try:
                        ch = int(line.split(':')[1].strip())
                        current['channel'] = ch
                        current['band'] = '5GHz' if ch > 14 else '2.4GHz'
                    except: pass
                elif 'Authentication' in line and ':' in line:
                    current['security'] = line.split(':')[1].strip()
            if current.get('ssid'): networks.append(current)

    except Exception as e:
        log.warning(f"Wi-Fi scan error: {e}")

    return networks

# ─────────────────────────────────────────────────────────────
# ISP / PUBLIC IP INFO
# ─────────────────────────────────────────────────────────────

def get_public_info():
    import urllib.request
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as r:
            data = json.loads(r.read())
            return {
                "public_ip": data.get("ip"),
                "isp": data.get("org", "").split(" ", 1)[-1],
                "city": data.get("city"),
                "country": data.get("country"),
                "hostname": data.get("hostname"),
                "timezone": data.get("timezone"),
            }
    except Exception:
        return {}

def get_dns_servers():
    servers = []
    try:
        if OS in ('Linux', 'Darwin'):
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        servers.append(line.split()[1])
        elif OS == 'Windows':
            out = subprocess.check_output(['ipconfig', '/all'], timeout=5).decode()
            for line in out.split('\n'):
                if 'DNS Servers' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        servers.append(parts[1].strip())
    except Exception:
        pass
    return servers or ['Unknown']

# ─────────────────────────────────────────────────────────────
# SYSTEM STATS
# ─────────────────────────────────────────────────────────────

def get_system_stats():
    stats = {"platform": OS, "python": sys.version.split()[0]}
    if HAS_PSUTIL:
        stats["cpu_percent"] = psutil.cpu_percent(interval=0.5)
        stats["mem_percent"] = psutil.virtual_memory().percent
        stats["net_io"] = {}
        io = psutil.net_io_counters(pernic=True)
        for iface, counters in io.items():
            stats["net_io"][iface] = {
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv
            }
    return stats

# ─────────────────────────────────────────────────────────────
# HTTP API SERVER
# ─────────────────────────────────────────────────────────────

scan_state = {
    "devices": [],
    "scanning": False,
    "scan_progress": 0,
    "scan_ip": "",
    "alerts": []
}

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logs

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]

        if path == '/api/interfaces':
            self.send_json(get_network_interfaces())

        elif path == '/api/devices':
            with state_lock:
                self.send_json(scan_state["devices"])

        elif path == '/api/scan/status':
            with state_lock:
                self.send_json({
                    "scanning": scan_state["scanning"],
                    "progress": scan_state["scan_progress"],
                    "current_ip": scan_state["scan_ip"],
                    "device_count": len(scan_state["devices"])
                })

        elif path == '/api/public':
            self.send_json(get_public_info())

        elif path == '/api/dns':
            self.send_json({"servers": get_dns_servers()})

        elif path == '/api/wifi':
            self.send_json(scan_wifi())

        elif path == '/api/system':
            self.send_json(get_system_stats())

        elif path == '/api/vulnerabilities':
            with state_lock:
                devices = list(scan_state["devices"])
            vulns = analyze_vulnerabilities(devices)
            self.send_json(vulns)

        elif path == '/api/alerts':
            with state_lock:
                self.send_json(scan_state["alerts"])

        elif path == '/api/speedtest':
            result = run_speed_test()
            self.send_json(result)

        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = self.path
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length) or b'{}')

        if path == '/api/scan/start':
            cidr = body.get('cidr', '')
            if not cidr:
                ifaces = get_network_interfaces()
                cidr = ifaces[0]['cidr'] if ifaces else '192.168.1.0/24'
            
            with state_lock:
                if scan_state["scanning"]:
                    self.send_json({"error": "Scan already in progress"}, 409)
                    return

            threading.Thread(target=run_scan_bg, args=(cidr,), daemon=True).start()
            self.send_json({"status": "started", "cidr": cidr})

        elif path == '/api/ports/scan':
            ip = body.get('ip')
            port_range = body.get('range', 'common')
            if not ip:
                self.send_json({"error": "ip required"}, 400)
                return
            if port_range == 'top100':
                ports = COMMON_PORTS[:100]
            elif port_range == 'full':
                ports = list(range(1, 1025)) + COMMON_PORTS
            else:
                ports = COMMON_PORTS
            results = full_port_scan(ip, ports)
            # Update device ports in state
            with state_lock:
                for d in scan_state["devices"]:
                    if d["ip"] == ip:
                        d["ports"] = [r["port"] for r in results]
            self.send_json(results)

        elif path == '/api/device/resolve':
            ip = body.get('ip')
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            self.send_json({"hostname": hostname})

        else:
            self.send_json({"error": "Not found"}, 404)

def run_scan_bg(cidr):
    with state_lock:
        if scan_state["scanning"]:
            log.warning("Scan already in progress, skipping")
            return
        scan_state["scanning"] = True
        scan_state["scan_progress"] = 0
        old_devices = list(scan_state["devices"])

    def progress(done, total, ip):
        with state_lock:
            scan_state["scan_progress"] = round((done / total) * 100)
            scan_state["scan_ip"] = ip

    devices = scan_network(cidr, progress_cb=progress)

    with state_lock:
        prev_ips = {d["ip"] for d in old_devices}
        for d in devices:
            if d["ip"] not in prev_ips:
                scan_state["alerts"].insert(0, {
                    "type": "new",
                    "time": datetime.now().strftime("%H:%M"),
                    "msg": "New device joined",
                    "sub": f"{d['name']} ({d['ip']}) — {d['mac']}"
                })

        scan_state["devices"] = devices
        scan_state["scanning"] = False
        scan_state["scan_progress"] = 100
        log.info(f"Scan complete: {len(devices)} devices found on {cidr}")

def start_server(port=7832):
    server = HTTPServer(('127.0.0.1', port), APIHandler)
    log.info(f"NetScan Pro API running on http://127.0.0.1:{port}")
    server.serve_forever()

if __name__ == '__main__':
    start_server()
