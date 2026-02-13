"""
RedScan AI - Core Scanner Engine
Phase 1: Network Reconnaissance Module
Phase 2: Website Reconnaissance Module  
Phase 3: Local Server Testing Module
Handles port scanning, service detection, banner grabbing, target discovery, web recon, and localhost testing
"""
import socket
import subprocess
import re
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import ipaddress
import requests
from datetime import datetime

# Try to import nmap, fallback to socket-based scanning
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[!] python-nmap not installed. Using fallback socket scanning.")

# Import local modules
from .web_recon import WebsiteRecon, WebVulnerabilityScanner
from .local_server_scanner import LocalServerScanner, DjangoSecurityAnalyzer, ComprehensiveLocalhostScanner
from .vulnerability_engine import AdvancedVulnerabilityEngine


class NetworkScanner:
    """
    Advanced Network Scanner with multiple scanning techniques
    Supports both Nmap and socket-based scanning
    """
    
    def __init__(self, target: str):
        self.target = target
        self.target_ip = None
        self.results = {
            'open_ports': [],
            'services': {},
            'banners': {},
            'os_detection': None,
            'scan_time': None,
        }
        
        # Initialize Nmap scanner if available
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def resolve_target(self) -> str:
        """
        Resolve hostname to IP address
        Returns IP address or original target if already an IP
        """
        try:
            # Check if already an IP
            ipaddress.ip_address(self.target)
            self.target_ip = self.target
            return self.target
        except ValueError:
            # It's a hostname, resolve it
            try:
                self.target_ip = socket.gethostbyname(self.target)
                print(f"[+] Resolved {self.target} to {self.target_ip}")
                return self.target_ip
            except socket.gaierror:
                print(f"[-] Could not resolve {self.target}")
                return None
    
    def scan_port_socket(self, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
        """
        Scan a single port using raw socket connection
        Returns: (port_number, is_open, service_name)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip or self.target, port))
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
    
    def scan_ports_socket(self, port_range, max_workers: int = 100) -> List[int]:
        """
        Scan multiple ports concurrently using sockets
        Fallback method when Nmap is not available
        Accepts both range objects and lists of ports
        """
        # Handle both range objects and lists
        if isinstance(port_range, range):
            print(f"[*] Socket scanning {self.target} ports {port_range.start}-{port_range.stop-1}...")
            ports_to_scan = port_range
        elif isinstance(port_range, list):
            print(f"[*] Socket scanning {self.target} specific ports: {', '.join(map(str, port_range))}...")
            ports_to_scan = port_range
        else:
            print(f"[*] Socket scanning {self.target} ports...")
            ports_to_scan = port_range
        
        start_time = datetime.now()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port_socket, port): port for port in ports_to_scan}
            
            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    self.results['open_ports'].append(port)
                    self.results['services'][port] = service
                    print(f"[+] Port {port}/tcp open - {service}")
        
        self.results['scan_time'] = (datetime.now() - start_time).total_seconds()
        return sorted(self.results['open_ports'])
    
    def scan_ports_nmap(self, port_range, scan_type: str = 'default') -> List[int]:
        """
        Scan ports using Nmap for more accurate results
        Scan types: 'default', 'stealth', 'aggressive', 'version'
        Accepts both range objects and lists of ports
        """
        if not self.nm:
            print("[!] Nmap not available, falling back to socket scan")
            return self.scan_ports_socket(port_range)
        
        # Handle both range objects and lists
        if isinstance(port_range, range):
            print(f"[*] Nmap scanning {self.target} ports {port_range.start}-{port_range.stop-1}...")
            port_str = f"{port_range.start}-{port_range.stop-1}"
        elif isinstance(port_range, list):
            print(f"[*] Nmap scanning {self.target} specific ports: {', '.join(map(str, port_range))}...")
            port_str = ','.join(map(str, port_range))
        else:
            print(f"[*] Nmap scanning {self.target} ports...")
            port_str = str(port_range)
        
        start_time = datetime.now()
        
        # Select scan arguments based on type
        scan_args = {
            'default': '-sS -sV',  # SYN scan with version detection
            'stealth': '-sS',       # Stealth SYN scan
            'aggressive': '-A',     # Aggressive scan (OS, version, scripts)
            'version': '-sV',       # Version detection
        }
        
        args = scan_args.get(scan_type, '-sS -sV')
        
        try:
            self.nm.scan(self.target, port_str, arguments=args)
            
            # Parse results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            self.results['open_ports'].append(port)
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            product = port_info.get('product', '')
                            
                            service_str = f"{product} {version}".strip() if product else service
                            self.results['services'][port] = service_str
                            
                            print(f"[+] Port {port}/tcp open - {service_str}")
                
                # OS Detection
                if 'osmatch' in self.nm[host]:
                    os_matches = self.nm[host]['osmatch']
                    if os_matches:
                        self.results['os_detection'] = os_matches[0]['name']
                        print(f"[+] OS Detection: {self.results['os_detection']}")
        
        except Exception as e:
            print(f"[-] Nmap scan error: {e}")
            print("[!] Falling back to socket scan")
            return self.scan_ports_socket(port_range)
        
        self.results['scan_time'] = (datetime.now() - start_time).total_seconds()
        return sorted(self.results['open_ports'])
    
    def scan_ports(self, port_range=range(1, 1025), use_nmap: bool = True) -> List[int]:
        """
        Main port scanning method
        Automatically chooses best scanning method
        Accepts both range objects and lists of ports
        """
        # Resolve target first
        if not self.resolve_target():
            return []
        
        # Use Nmap if available and requested
        if use_nmap and NMAP_AVAILABLE:
            return self.scan_ports_nmap(port_range)
        else:
            return self.scan_ports_socket(port_range)
    
    def banner_grab(self, port: int, timeout: float = 2.0) -> str:
        """
        Grab service banner for version detection
        Supports HTTP, FTP, SMTP, SSH, and generic TCP services
        """
        banner = ""
        target = self.target_ip or self.target
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # HTTP/HTTPS banner grabbing
            if port in [80, 443, 8080, 8443, 8000, 3000, 5000]:
                request = b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
                sock.send(request)
                banner = sock.recv(2048).decode('utf-8', errors='ignore')
            
            # FTP banner
            elif port == 21:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # SSH banner
            elif port == 22:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # SMTP banner
            elif port in [25, 587]:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Generic banner grab
            else:
                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            
            sock.close()
            
            if banner:
                self.results['banners'][port] = banner.strip()
                print(f"[+] Banner from port {port}: {banner[:100]}...")
            
            return banner.strip()
        
        except Exception as e:
            return ""
    
    def grab_all_banners(self) -> Dict[int, str]:
        """Grab banners from all open ports"""
        print("[*] Grabbing service banners...")
        for port in self.results['open_ports']:
            self.banner_grab(port)
        return self.results['banners']
    
    def detect_web_server(self, port: int) -> Dict:
        """
        Detect web server type and version
        """
        target = self.target_ip or self.target
        protocols = ['https' if port in [443, 8443] else 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{target}:{port}"
                response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                
                return {
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                    'status_code': response.status_code,
                    'title': self._extract_title(response.text),
                }
            except:
                continue
        
        return {}
    
    @staticmethod
    def _extract_title(html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else 'No title'


class TargetDiscovery:
    """
    Target Discovery Module
    Handles DNS enumeration, subdomain discovery, and network mapping
    """
    
    def __init__(self, domain: str):
        self.domain = domain
        self.discovered_hosts = []
    
    def dns_lookup(self, record_type: str = 'A') -> List[str]:
        """
        Perform DNS lookup for various record types
        Types: A, AAAA, MX, NS, TXT, CNAME
        """
        results = []
        try:
            answers = dns.resolver.resolve(self.domain, record_type)
            for rdata in answers:
                results.append(str(rdata))
                print(f"[+] {record_type} record: {rdata}")
        except Exception as e:
            print(f"[-] DNS lookup failed for {record_type}: {e}")
        
        return results
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"[+] Reverse DNS: {ip} -> {hostname}")
            return hostname
        except:
            return None
    
    def subdomain_enumeration(self, wordlist: List[str] = None) -> List[str]:
        """
        Enumerate subdomains using DNS queries
        """
        if wordlist is None:
            # Common subdomain wordlist
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'admin', 'portal', 'api', 'dev', 'staging', 'test', 'demo', 'blog',
                'shop', 'forum', 'support', 'vpn', 'remote', 'cloud', 'cdn', 'app'
            ]
        
        print(f"[*] Enumerating subdomains for {self.domain}...")
        found_subdomains = []
        
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for rdata in answers:
                    found_subdomains.append({
                        'subdomain': full_domain,
                        'ip': str(rdata)
                    })
                    print(f"[+] Found: {full_domain} -> {rdata}")
            except:
                pass
        
        self.discovered_hosts = found_subdomains
        return found_subdomains
    
    def get_mx_records(self) -> List[str]:
        """Get mail server records"""
        return self.dns_lookup('MX')
    
    def get_ns_records(self) -> List[str]:
        """Get nameserver records"""
        return self.dns_lookup('NS')
    
    def get_txt_records(self) -> List[str]:
        """Get TXT records (SPF, DKIM, etc.)"""
        return self.dns_lookup('TXT')


class VulnerabilityScanner:
    """
    Vulnerability Detection Engine
    Identifies common security issues and misconfigurations
    """
    
    def __init__(self, target: str, open_ports: List[int]):
        self.target = target
        self.open_ports = open_ports
        self.vulnerabilities = []
    
    def check_common_vulnerabilities(self) -> List[Dict]:
        """
        Check for common vulnerabilities and misconfigurations
        """
        print(f"[*] Analyzing vulnerabilities on {self.target}...")
        
        # Dangerous/risky open ports
        risky_ports = {
            21: ('FTP', 'Unencrypted file transfer protocol', 'medium', 
                 'Use SFTP or FTPS instead'),
            23: ('Telnet', 'Unencrypted remote access', 'high',
                 'Use SSH instead of Telnet'),
            25: ('SMTP', 'Mail server exposed', 'low',
                 'Ensure proper authentication and relay controls'),
            445: ('SMB', 'File sharing protocol - potential for exploits', 'critical',
                  'Restrict SMB access and apply latest patches'),
            1433: ('MSSQL', 'Database server exposed', 'high',
                   'Restrict database access to trusted IPs only'),
            3306: ('MySQL', 'Database server exposed', 'high',
                   'Restrict database access to trusted IPs only'),
            3389: ('RDP', 'Remote Desktop exposed to internet', 'critical',
                   'Use VPN or restrict RDP access by IP'),
            5432: ('PostgreSQL', 'Database server exposed', 'high',
                   'Restrict database access to trusted IPs only'),
            5900: ('VNC', 'Remote desktop protocol exposed', 'high',
                   'Use strong passwords and consider VPN access'),
            6379: ('Redis', 'In-memory database exposed', 'critical',
                   'Enable authentication and bind to localhost'),
            27017: ('MongoDB', 'Database exposed without authentication', 'critical',
                    'Enable authentication and restrict network access'),
        }
        
        for port in self.open_ports:
            if port in risky_ports:
                service, desc, severity, remediation = risky_ports[port]
                self.vulnerabilities.append({
                    'port': port,
                    'title': f'{service} Service Exposed',
                    'description': desc,
                    'severity': severity,
                    'remediation': remediation
                })
        
        # Check for common web ports
        web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000]
        for port in self.open_ports:
            if port in web_ports:
                self.vulnerabilities.append({
                    'port': port,
                    'title': f'Web Server on Port {port}',
                    'description': 'Web service detected - ensure proper security headers and HTTPS',
                    'severity': 'info',
                    'remediation': 'Implement HTTPS, security headers, and regular security audits'
                })
        
        # SSH detection
        if 22 in self.open_ports:
            self.vulnerabilities.append({
                'port': 22,
                'title': 'SSH Service Detected',
                'description': 'Secure Shell service is running',
                'severity': 'info',
                'remediation': 'Use key-based authentication, disable root login, change default port'
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
        max_possible = len(self.vulnerabilities) * 10
        return min(10.0, (total_score / max_possible) * 10)


class LocalReconEngine:
    """
    Local Server Reconnaissance Engine
    Comprehensive localhost testing covering all scenarios:
    - Web Development (React, Vue, Angular, Django, Flask)
    - Testing Environments (XAMPP, WAMP, Docker)
    - API Testing (REST, GraphQL)
    - Container Testing
    - Internal Network Testing
    """
    
    def __init__(self, target: str = 'localhost', progress_callback=None):
        self.target = target
        self.progress_callback = progress_callback
        self.comprehensive_scanner = ComprehensiveLocalhostScanner(target, progress_callback)
        self.django_analyzer = DjangoSecurityAnalyzer()
        self.results = {}
    
    def adaptive_local_scan(self, scan_type: str = 'comprehensive') -> Dict:
        """
        Adaptive scanning for all localhost scenarios with 1% increments
        Scan types: 'comprehensive', 'web_dev', 'testing_env', 'containers', 'apis'
        """
        print(f"\n{'='*60}")
        print(f"RedScan AI - Comprehensive Localhost Reconnaissance")
        print(f"Target: {self.target}")
        print(f"Scan Type: {scan_type}")
        print(f"{'='*60}\n")
        
        if scan_type == 'comprehensive':
            return self.comprehensive_localhost_scan()
        elif scan_type == 'web_dev':
            return self.web_development_scan()
        elif scan_type == 'testing_env':
            return self.testing_environment_scan()
        elif scan_type == 'containers':
            return self.container_scan()
        elif scan_type == 'apis':
            return self.api_scan()
        else:
            return self.comprehensive_localhost_scan()  # Default
    
    def comprehensive_localhost_scan(self) -> Dict:
        """
        Comprehensive localhost scanning covering all scenarios
        """
        # Run the comprehensive scan
        results = self.comprehensive_scanner.run_comprehensive_scan()
        
        # Add Django-specific analysis if Django is detected
        django_detected = any(
            server.get('framework') == 'Django' 
            for server in results.get('development_servers', [])
        )
        
        if django_detected:
            if self.progress_callback:
                self.progress_callback(98, "Adding Django-specific analysis...")
            
            django_file_issues = self.django_analyzer.analyze_settings_file()
            if django_file_issues:
                for issue in django_file_issues:
                    results['vulnerabilities'].append({
                        'type': f'Django Configuration: {issue["issue"]}',
                        'severity': issue['severity'],
                        'description': f"Security issue in {issue['file']}: {issue['issue']}",
                        'category': 'Django Security'
                    })
        
        if self.progress_callback:
            self.progress_callback(100, "Comprehensive localhost scan completed!")
        
        self.results = results
        return results
    
    def web_development_scan(self) -> Dict:
        """
        Focused scan for web development servers
        """
        results = {
            'target': self.target,
            'scan_type': 'Web Development',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'development_servers': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Web development specific scanning with detailed progress
        web_dev_ports = [3000, 3001, 4200, 5000, 5173, 8000, 8080, 9000]
        
        for i, port in enumerate(web_dev_ports):
            progress = int((i + 1) / len(web_dev_ports) * 90)  # 90% for port scanning
            if self.progress_callback:
                self.progress_callback(progress, f"Scanning web development port {port}...")
            
            if self.comprehensive_scanner.check_port(port):
                server_info = self.comprehensive_scanner.analyze_development_server({
                    'port': port,
                    'name': f'Development Server {port}',
                    'endpoints': ['/', '/api/', '/static/']
                })
                if server_info:
                    results['development_servers'].append(server_info)
        
        # Generate web development specific recommendations
        if self.progress_callback:
            self.progress_callback(95, "Generating web development recommendations...")
        
        for server in results['development_servers']:
            if server.get('debug_mode'):
                results['vulnerabilities'].append({
                    'type': 'Development Debug Mode',
                    'severity': 'High',
                    'description': f'{server["name"]} running in debug mode'
                })
        
        if self.progress_callback:
            self.progress_callback(100, "Web development scan completed!")
        
        return results
    
    def testing_environment_scan(self) -> Dict:
        """
        Focused scan for testing environments (XAMPP, WAMP, etc.)
        """
        results = {
            'target': self.target,
            'scan_type': 'Testing Environment',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'testing_environments': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Testing environment specific scanning
        testing_ports = [80, 443, 3306, 5432, 6379, 8080, 27017]
        
        for i, port in enumerate(testing_ports):
            progress = int((i + 1) / len(testing_ports) * 80)
            if self.progress_callback:
                self.progress_callback(progress, f"Scanning testing environment port {port}...")
            
            if self.comprehensive_scanner.check_port(port):
                # Analyze testing environment
                env_info = self.analyze_testing_port(port)
                if env_info:
                    results['testing_environments'].append(env_info)
        
        # Check for common testing vulnerabilities
        if self.progress_callback:
            self.progress_callback(90, "Checking testing environment vulnerabilities...")
        
        # Add testing-specific vulnerability checks
        for env in results['testing_environments']:
            if 'admin' in env.get('name', '').lower():
                results['vulnerabilities'].append({
                    'type': 'Admin Interface Exposed',
                    'severity': 'High',
                    'description': f'Admin interface accessible: {env["name"]}'
                })
        
        if self.progress_callback:
            self.progress_callback(100, "Testing environment scan completed!")
        
        return results
    
    def analyze_testing_port(self, port):
        """Analyze a specific testing environment port"""
        port_services = {
            80: 'XAMPP/WAMP Apache',
            443: 'XAMPP/WAMP Apache SSL',
            3306: 'MySQL Database',
            5432: 'PostgreSQL Database',
            6379: 'Redis Cache',
            8080: 'Jenkins/Tomcat',
            27017: 'MongoDB Database'
        }
        
        return {
            'port': port,
            'name': port_services.get(port, f'Service on port {port}'),
            'accessible': True,
            'type': 'database' if port in [3306, 5432, 6379, 27017] else 'web'
        }
    
    def container_scan(self) -> Dict:
        """
        Focused scan for container environments
        """
        results = {
            'target': self.target,
            'scan_type': 'Container Environment',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'containers': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        container_ports = [2375, 2376, 9000, 8080]
        
        for i, port in enumerate(container_ports):
            progress = int((i + 1) / len(container_ports) * 70)
            if self.progress_callback:
                self.progress_callback(progress, f"Scanning container port {port}...")
            
            if self.comprehensive_scanner.check_port(port):
                container_info = self.analyze_container_port(port)
                results['containers'].append(container_info)
        
        # Container security analysis
        if self.progress_callback:
            self.progress_callback(80, "Analyzing container security...")
        
        for container in results['containers']:
            if container['port'] == 2375:
                results['vulnerabilities'].append({
                    'type': 'Insecure Docker API',
                    'severity': 'Critical',
                    'description': 'Docker API exposed without authentication'
                })
        
        if self.progress_callback:
            self.progress_callback(100, "Container scan completed!")
        
        return results
    
    def analyze_container_port(self, port):
        """Analyze container-specific port"""
        container_services = {
            2375: 'Docker API (Insecure)',
            2376: 'Docker API (Secure)',
            9000: 'Portainer',
            8080: 'Container Web Interface'
        }
        
        return {
            'port': port,
            'name': container_services.get(port, f'Container service {port}'),
            'risk_level': 'Critical' if port == 2375 else 'Medium'
        }
    
    def api_scan(self) -> Dict:
        """
        Focused scan for API endpoints
        """
        results = {
            'target': self.target,
            'scan_type': 'API Testing',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'apis': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        api_ports = [3000, 5000, 8000, 8080, 9000]
        
        for i, port in enumerate(api_ports):
            progress = int((i + 1) / len(api_ports) * 60)
            if self.progress_callback:
                self.progress_callback(progress, f"Scanning API endpoints on port {port}...")
            
            if self.comprehensive_scanner.check_port(port):
                api_info = self.analyze_api_port(port)
                if api_info:
                    results['apis'].append(api_info)
        
        # API security analysis
        if self.progress_callback:
            self.progress_callback(70, "Analyzing API security...")
        
        for api in results['apis']:
            if '/docs/' in api.get('endpoints', []):
                results['vulnerabilities'].append({
                    'type': 'API Documentation Exposed',
                    'severity': 'Medium',
                    'description': f'API documentation accessible on port {api["port"]}'
                })
        
        if self.progress_callback:
            self.progress_callback(100, "API scan completed!")
        
        return results
    
    def analyze_api_port(self, port):
        """Analyze API endpoints on a specific port"""
        base_url = f"http://{self.target}:{port}"
        api_paths = ['/api/', '/rest/', '/graphql/', '/docs/', '/swagger/']
        
        accessible_endpoints = []
        for path in api_paths:
            if self.comprehensive_scanner.test_endpoint(urljoin(base_url, path)):
                accessible_endpoints.append(path)
        
        if accessible_endpoints:
            return {
                'port': port,
                'base_url': base_url,
                'endpoints': accessible_endpoints
            }
        return None


class ReconEngine:
    """
    Advanced Reconnaissance Engine
    Combines all recon modules for comprehensive target analysis
    Now includes local server testing capabilities
    """
    
    def __init__(self, target: str):
        self.target = target
        self.scanner = NetworkScanner(target)
        self.local_engine = LocalReconEngine(target) if target in ['localhost', '127.0.0.1'] else None
        self.results = {}
    
    def adaptive_scan(self, scan_type: str = 'network', progress_callback=None) -> Dict:
        """
        Adaptive scanning based on target and scan type
        Scan types: 'network', 'web', 'api', 'localhost', 'vulnerability'
        Features 1% increment progress tracking
        """
        if scan_type == 'localhost' or self.target in ['localhost', '127.0.0.1']:
            # Use local server scanning
            local_engine = LocalReconEngine(self.target, progress_callback)
            return local_engine.adaptive_local_scan('comprehensive')
        
        elif scan_type == 'vulnerability':
            return self.vulnerability_scan_with_progress(progress_callback)
        
        elif scan_type == 'network':
            return self.network_scan_with_progress(progress_callback)
        
        elif scan_type == 'web':
            return self.web_scan_with_progress(progress_callback)
        
        elif scan_type == 'api':
            return self.api_scan_with_progress(progress_callback)
        
        else:
            return self.full_recon()
    
    def vulnerability_scan_with_progress(self, progress_callback=None) -> Dict:
        """Advanced vulnerability scanning with 1% increments"""
        # Initialize vulnerability engine
        vuln_engine = AdvancedVulnerabilityEngine(self.target, progress_callback)
        return vuln_engine.run_comprehensive_vulnerability_scan()
    
    def network_scan_with_progress(self, progress_callback=None) -> Dict:
        """Network scanning with 1% increments"""
        total_steps = 100
        current_step = 0
        
        def update_progress(increment=1, status="Scanning..."):
            nonlocal current_step
            current_step += increment
            if current_step > total_steps:
                current_step = total_steps
            if progress_callback:
                progress_callback(current_step, status)
        
        # Phase 1: Target Resolution (5%)
        update_progress(5, "Resolving target...")
        ip = self.scanner.resolve_target()
        if not ip:
            return {'error': 'Could not resolve target'}
        
        # Phase 2: Port Scanning (60%)
        update_progress(5, "Starting port scan...")
        port_range = range(1, 1025)
        ports_per_step = len(port_range) // 50  # 50 steps for port scanning
        
        open_ports = []
        for i, port in enumerate(port_range):
            if i % ports_per_step == 0:
                update_progress(1, f"Scanning port {port}...")
            
            # Perform actual port scan
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        # Phase 3: Service Detection (20%)
        update_progress(5, "Detecting services...")
        services = {}
        for i, port in enumerate(open_ports):
            try:
                service = socket.getservbyport(port)
                services[port] = service
            except:
                services[port] = 'unknown'
            
            if len(open_ports) > 0:
                progress_increment = 15 // len(open_ports)
                update_progress(progress_increment, f"Analyzing service on port {port}")
        
        # Phase 4: Vulnerability Assessment (10%)
        update_progress(5, "Assessing vulnerabilities...")
        vuln_scanner = VulnerabilityScanner(self.target, open_ports)
        vulnerabilities = vuln_scanner.check_common_vulnerabilities()
        risk_score = vuln_scanner.calculate_risk_score()
        update_progress(5, "Vulnerability assessment complete")
        
        # Compile results
        results = {
            'target': self.target,
            'ip': ip,
            'scan_type': 'Network',
            'open_ports': open_ports,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return results
    
    def web_scan_with_progress(self, progress_callback=None) -> Dict:
        """Web scanning with 1% increments"""
        # Initialize web reconnaissance
        web_recon = WebsiteRecon(self.target, progress_callback)
        return web_recon.comprehensive_scan()
    
    def api_scan_with_progress(self, progress_callback=None) -> Dict:
        """API scanning with 1% increments"""
        # Placeholder for API scanning - can be expanded
        total_steps = 100
        
        for i in range(total_steps):
            if progress_callback:
                progress_callback(i + 1, f"API scanning step {i + 1}/100")
        
        return {
            'target': self.target,
            'scan_type': 'API',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'api_endpoints': [],
            'authentication': {},
            'vulnerabilities': []
        }
    
    def full_recon(self, port_range: range = range(1, 1025)) -> Dict:
        """
        Perform full reconnaissance on target
        """
        print(f"\n{'='*60}")
        print(f"RedScan AI - Full Reconnaissance")
        print(f"Target: {self.target}")
        print(f"{'='*60}\n")
        
        # Phase 1: Target Resolution
        print("[Phase 1] Target Resolution")
        ip = self.scanner.resolve_target()
        if not ip:
            return {'error': 'Could not resolve target'}
        
        # Phase 2: Port Scanning
        print(f"\n[Phase 2] Port Scanning")
        open_ports = self.scanner.scan_ports(port_range)
        
        # Phase 3: Banner Grabbing
        print(f"\n[Phase 3] Service Detection")
        self.scanner.grab_all_banners()
        
        # Phase 4: Vulnerability Assessment
        print(f"\n[Phase 4] Vulnerability Assessment")
        vuln_scanner = VulnerabilityScanner(self.target, open_ports)
        vulnerabilities = vuln_scanner.check_common_vulnerabilities()
        risk_score = vuln_scanner.calculate_risk_score()
        
        # Compile results
        self.results = {
            'target': self.target,
            'ip': ip,
            'open_ports': open_ports,
            'services': self.scanner.results['services'],
            'banners': self.scanner.results['banners'],
            'os_detection': self.scanner.results['os_detection'],
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score,
            'scan_time': self.scanner.results['scan_time'],
        }
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Open Ports: {len(open_ports)}")
        print(f"Vulnerabilities: {len(vulnerabilities)}")
        print(f"Risk Score: {risk_score:.1f}/10")
        print(f"Scan Time: {self.scanner.results['scan_time']:.2f}s")
        print(f"{'='*60}\n")
        
        return self.results
