"""
Core scanning engine for RedScan AI
Handles network reconnaissance and vulnerability detection
"""
import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
import ipaddress

class NetworkScanner:
    """Handles network reconnaissance tasks"""
    
    def __init__(self, target: str):
        self.target = target
        self.results = {
            'open_ports': [],
            'services': {},
            'os_detection': None,
        }
    
    def scan_port(self, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
        """
        Scan a single port using socket connection
        Returns: (port_number, is_open, service_name)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                return (port, True, service)
            return (port, False, '')
        except Exception as e:
            return (port, False, '')
    
    def scan_ports(self, port_range: range = range(1, 1025), max_workers: int = 100):
        """
        Scan multiple ports concurrently
        Default: scans common ports 1-1024
        """
        print(f"[*] Scanning {self.target} for open ports...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in port_range}
            
            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    self.results['open_ports'].append(port)
                    self.results['services'][port] = service
                    print(f"[+] Port {port} is open - {service}")
        
        return self.results['open_ports']
    
    def banner_grab(self, port: int, timeout: float = 2.0) -> str:
        """
        Attempt to grab service banner for version detection
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target, port))
            
            # Send HTTP request for web servers
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return ""
    
    def resolve_hostname(self) -> str:
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(self.target)
        except:
            return self.target

class VulnerabilityScanner:
    """Detects common vulnerabilities"""
    
    def __init__(self, target: str, open_ports: List[int]):
        self.target = target
        self.open_ports = open_ports
        self.vulnerabilities = []
    
    def check_common_vulnerabilities(self) -> List[Dict]:
        """
        Check for common misconfigurations and vulnerabilities
        """
        print(f"[*] Checking for vulnerabilities on {self.target}...")
        
        # Check for dangerous open ports
        dangerous_ports = {
            21: ('FTP', 'Unencrypted file transfer', 'medium'),
            23: ('Telnet', 'Unencrypted remote access', 'high'),
            445: ('SMB', 'Potential for EternalBlue exploit', 'critical'),
            3389: ('RDP', 'Remote Desktop exposed', 'high'),
            5900: ('VNC', 'Remote desktop exposed', 'high'),
        }
        
        for port in self.open_ports:
            if port in dangerous_ports:
                service, desc, severity = dangerous_ports[port]
                self.vulnerabilities.append({
                    'port': port,
                    'title': f'{service} Service Exposed',
                    'description': desc,
                    'severity': severity,
                    'remediation': f'Consider disabling {service} or restricting access via firewall'
                })
        
        # Check for default credentials (simulated)
        if 22 in self.open_ports:
            self.vulnerabilities.append({
                'port': 22,
                'title': 'SSH Service Detected',
                'description': 'Ensure strong authentication is configured',
                'severity': 'info',
                'remediation': 'Use key-based authentication and disable password login'
            })
        
        return self.vulnerabilities
    
    def calculate_risk_score(self) -> float:
        """
        Calculate overall risk score (0-10) based on findings
        """
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 0.5
        }
        
        if not self.vulnerabilities:
            return 0.0
        
        total_score = sum(severity_weights.get(v['severity'], 0) for v in self.vulnerabilities)
        # Normalize to 0-10 scale
        return min(10.0, total_score / len(self.vulnerabilities))

class ReconEngine:
    """Advanced reconnaissance features"""
    
    @staticmethod
    def whois_lookup(domain: str) -> Dict:
        """Placeholder for WHOIS information gathering"""
        return {
            'domain': domain,
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'note': 'Implement with python-whois library'
        }
    
    @staticmethod
    def subdomain_enum(domain: str) -> List[str]:
        """Placeholder for subdomain enumeration"""
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev']
        found = []
        
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                found.append(full_domain)
            except:
                pass
        
        return found
