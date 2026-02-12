"""
RedScan AI - Website Reconnaissance Module
Phase 2: Web Application Scanning
Handles URL crawling, directory enumeration, header analysis, and technology detection
"""
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class WebsiteRecon:
    """
    Comprehensive Website Reconnaissance Scanner
    Analyzes web applications for structure, technologies, and potential vulnerabilities
    """
    
    def __init__(self, base_url: str, timeout: int = 5):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedScan-AI/1.0 (Security Scanner)'
        })
        
        # Results storage
        self.discovered_urls = set()
        self.technologies = {}
        self.headers = {}
        self.directories = []
        self.forms = []
        
    def analyze_headers(self, url: str = None) -> Dict:
        """
        Analyze HTTP response headers for security and technology information
        """
        target_url = url or self.base_url
        print(f"[*] Analyzing headers for {target_url}")
        
        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = dict(response.headers)
            
            # Security headers analysis
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            }
            
            # Technology detection from headers
            tech_headers = {
                'Server': headers.get('Server', 'Unknown'),
                'X-Powered-By': headers.get('X-Powered-By', 'Unknown'),
                'X-AspNet-Version': headers.get('X-AspNet-Version', 'Unknown'),
                'X-AspNetMvc-Version': headers.get('X-AspNetMvc-Version', 'Unknown'),
            }
            
            self.headers = {
                'all_headers': headers,
                'security_headers': security_headers,
                'technology_headers': tech_headers,
                'status_code': response.status_code,
                'content_type': headers.get('Content-Type', 'Unknown'),
            }
            
            # Print findings
            print(f"[+] Status Code: {response.status_code}")
            print(f"[+] Server: {tech_headers['Server']}")
            
            # Check for missing security headers
            missing_security = [k for k, v in security_headers.items() if v == 'Missing']
            if missing_security:
                print(f"[!] Missing security headers: {', '.join(missing_security)}")
            
            return self.headers
            
        except Exception as e:
            print(f"[-] Header analysis failed: {e}")
            return {}
    
    def detect_technologies(self, url: str = None) -> Dict:
        """
        Detect web technologies, frameworks, and CMS
        Similar to Wappalyzer
        """
        target_url = url or self.base_url
        print(f"[*] Detecting technologies on {target_url}")
        
        technologies = {
            'cms': [],
            'frameworks': [],
            'javascript_libraries': [],
            'web_servers': [],
            'programming_languages': [],
            'analytics': [],
        }
        
        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False)
            html = response.text
            headers = response.headers
            
            # CMS Detection
            cms_patterns = {
                'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
                'Joomla': [r'Joomla!', r'/components/com_'],
                'Drupal': [r'Drupal', r'/sites/default/'],
                'Magento': [r'Mage.Cookies', r'/skin/frontend/'],
                'Shopify': [r'cdn.shopify.com', r'Shopify'],
                'Wix': [r'wix.com', r'_wix'],
            }
            
            for cms, patterns in cms_patterns.items():
                if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                    technologies['cms'].append(cms)
                    print(f"[+] CMS Detected: {cms}")
            
            # JavaScript Libraries
            js_libraries = {
                'jQuery': r'jquery',
                'React': r'react',
                'Angular': r'angular',
                'Vue.js': r'vue',
                'Bootstrap': r'bootstrap',
                'Tailwind CSS': r'tailwind',
            }
            
            for lib, pattern in js_libraries.items():
                if re.search(pattern, html, re.IGNORECASE):
                    technologies['javascript_libraries'].append(lib)
                    print(f"[+] JS Library: {lib}")
            
            # Web Servers (from headers)
            server = headers.get('Server', '')
            if server:
                if 'nginx' in server.lower():
                    technologies['web_servers'].append('Nginx')
                elif 'apache' in server.lower():
                    technologies['web_servers'].append('Apache')
                elif 'iis' in server.lower():
                    technologies['web_servers'].append('IIS')
                elif 'cloudflare' in server.lower():
                    technologies['web_servers'].append('Cloudflare')
            
            # Programming Languages
            powered_by = headers.get('X-Powered-By', '')
            if 'PHP' in powered_by:
                technologies['programming_languages'].append(f'PHP {powered_by}')
            elif 'ASP.NET' in powered_by:
                technologies['programming_languages'].append('ASP.NET')
            
            # Analytics
            analytics_patterns = {
                'Google Analytics': r'google-analytics\.com|gtag\(',
                'Google Tag Manager': r'googletagmanager\.com',
                'Facebook Pixel': r'facebook\.net/en_US/fbevents\.js',
                'Hotjar': r'hotjar\.com',
            }
            
            for analytics, pattern in analytics_patterns.items():
                if re.search(pattern, html, re.IGNORECASE):
                    technologies['analytics'].append(analytics)
            
            self.technologies = technologies
            return technologies
            
        except Exception as e:
            print(f"[-] Technology detection failed: {e}")
            return technologies
    
    def crawl_website(self, max_depth: int = 2, max_urls: int = 50) -> Set[str]:
        """
        Crawl website to discover URLs and pages
        """
        print(f"[*] Crawling {self.base_url} (max depth: {max_depth}, max URLs: {max_urls})")
        
        to_visit = [(self.base_url, 0)]
        visited = set()
        
        while to_visit and len(self.discovered_urls) < max_urls:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                self.discovered_urls.add(url)
                print(f"[+] Found: {url}")
                
                if depth < max_depth:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Only crawl same domain
                        if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                            if full_url not in visited:
                                to_visit.append((full_url, depth + 1))
                
            except Exception as e:
                print(f"[-] Error crawling {url}: {e}")
                continue
        
        print(f"[+] Crawling complete. Found {len(self.discovered_urls)} URLs")
        return self.discovered_urls
    
    def enumerate_directories(self, wordlist: List[str] = None, max_workers: int = 10) -> List[Dict]:
        """
        Enumerate common directories and files
        """
        if wordlist is None:
            # Common directory wordlist
            wordlist = [
                'admin', 'administrator', 'login', 'wp-admin', 'dashboard',
                'api', 'backup', 'backups', 'config', 'database', 'db',
                'uploads', 'images', 'files', 'download', 'downloads',
                'test', 'dev', 'staging', 'beta', 'demo',
                'phpmyadmin', 'mysql', 'sql', 'old', 'new',
                'temp', 'tmp', 'cache', 'logs', 'log',
                '.git', '.env', '.htaccess', 'robots.txt', 'sitemap.xml',
                'wp-config.php', 'config.php', 'settings.php',
            ]
        
        print(f"[*] Enumerating directories on {self.base_url}")
        found_directories = []
        
        def check_path(path):
            url = f"{self.base_url}/{path}"
            try:
                response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'size': len(response.content),
                        'path': path
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_path, path): path for path in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_directories.append(result)
                    status = result['status_code']
                    size = result['size']
                    print(f"[+] [{status}] {result['url']} ({size} bytes)")
        
        self.directories = found_directories
        print(f"[+] Found {len(found_directories)} accessible paths")
        return found_directories
    
    def extract_forms(self, url: str = None) -> List[Dict]:
        """
        Extract and analyze HTML forms
        """
        target_url = url or self.base_url
        print(f"[*] Extracting forms from {target_url}")
        
        forms = []
        
        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                # Extract input fields
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name', '')
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                    })
                
                forms.append(form_details)
                print(f"[+] Form found: {form_details['method']} {form_details['action']}")
            
            self.forms = forms
            return forms
            
        except Exception as e:
            print(f"[-] Form extraction failed: {e}")
            return []
    
    def extract_emails(self, url: str = None) -> List[str]:
        """
        Extract email addresses from webpage
        """
        target_url = url or self.base_url
        print(f"[*] Extracting emails from {target_url}")
        
        emails = set()
        
        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False)
            
            # Email regex pattern
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            found_emails = re.findall(email_pattern, response.text)
            
            emails.update(found_emails)
            
            for email in emails:
                print(f"[+] Email found: {email}")
            
            return list(emails)
            
        except Exception as e:
            print(f"[-] Email extraction failed: {e}")
            return []
    
    def check_robots_txt(self) -> Dict:
        """
        Check and parse robots.txt file
        """
        robots_url = f"{self.base_url}/robots.txt"
        print(f"[*] Checking {robots_url}")
        
        try:
            response = requests.get(robots_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                print(f"[+] robots.txt found")
                
                # Parse disallowed paths
                disallowed = []
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed.append(path)
                            print(f"[+] Disallowed: {path}")
                
                return {
                    'exists': True,
                    'content': response.text,
                    'disallowed_paths': disallowed
                }
            else:
                print(f"[-] robots.txt not found")
                return {'exists': False}
                
        except Exception as e:
            print(f"[-] Error checking robots.txt: {e}")
            return {'exists': False}
    
    def check_sitemap(self) -> Dict:
        """
        Check for sitemap.xml
        """
        sitemap_url = f"{self.base_url}/sitemap.xml"
        print(f"[*] Checking {sitemap_url}")
        
        try:
            response = requests.get(sitemap_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                print(f"[+] sitemap.xml found")
                
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                print(f"[+] Found {len(urls)} URLs in sitemap")
                
                return {
                    'exists': True,
                    'urls': urls[:20],  # Limit to first 20
                    'total_urls': len(urls)
                }
            else:
                print(f"[-] sitemap.xml not found")
                return {'exists': False}
                
        except Exception as e:
            print(f"[-] Error checking sitemap: {e}")
            return {'exists': False}
    
    def full_web_recon(self) -> Dict:
        """
        Perform comprehensive website reconnaissance
        """
        print(f"\n{'='*60}")
        print(f"RedScan AI - Website Reconnaissance")
        print(f"Target: {self.base_url}")
        print(f"{'='*60}\n")
        
        results = {
            'target': self.base_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Phase 1: Header Analysis
        print("\n[Phase 1] HTTP Header Analysis")
        results['headers'] = self.analyze_headers()
        
        # Phase 2: Technology Detection
        print("\n[Phase 2] Technology Detection")
        results['technologies'] = self.detect_technologies()
        
        # Phase 3: robots.txt & sitemap.xml
        print("\n[Phase 3] Standard Files")
        results['robots_txt'] = self.check_robots_txt()
        results['sitemap'] = self.check_sitemap()
        
        # Phase 4: Directory Enumeration
        print("\n[Phase 4] Directory Enumeration")
        results['directories'] = self.enumerate_directories()
        
        # Phase 5: Form Extraction
        print("\n[Phase 5] Form Analysis")
        results['forms'] = self.extract_forms()
        
        # Phase 6: Email Extraction
        print("\n[Phase 6] Email Extraction")
        results['emails'] = self.extract_emails()
        
        # Phase 7: URL Crawling (limited)
        print("\n[Phase 7] URL Discovery")
        results['discovered_urls'] = list(self.crawl_website(max_depth=1, max_urls=20))
        
        print(f"\n{'='*60}")
        print(f"Web Reconnaissance Complete!")
        print(f"Technologies: {sum(len(v) for v in results['technologies'].values())}")
        print(f"Directories: {len(results['directories'])}")
        print(f"Forms: {len(results['forms'])}")
        print(f"URLs: {len(results['discovered_urls'])}")
        print(f"{'='*60}\n")
        
        return results


class WebVulnerabilityScanner:
    """
    Web-specific vulnerability scanner
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.vulnerabilities = []
    
    def check_security_headers(self, headers: Dict) -> List[Dict]:
        """
        Check for missing security headers
        """
        security_headers = headers.get('security_headers', {})
        
        for header, value in security_headers.items():
            if value == 'Missing':
                self.vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'title': f'Missing {header}',
                    'severity': 'medium',
                    'description': f'The {header} security header is not set',
                    'remediation': f'Add {header} header to HTTP responses'
                })
        
        return self.vulnerabilities
    
    def check_exposed_files(self, directories: List[Dict]) -> List[Dict]:
        """
        Check for exposed sensitive files
        """
        sensitive_files = ['.git', '.env', 'config.php', 'wp-config.php', 'database']
        
        for dir_info in directories:
            path = dir_info['path']
            if any(sensitive in path for sensitive in sensitive_files):
                if dir_info['status_code'] == 200:
                    self.vulnerabilities.append({
                        'type': 'Exposed Sensitive File',
                        'title': f'Exposed: {path}',
                        'severity': 'high',
                        'description': f'Sensitive file {path} is publicly accessible',
                        'remediation': 'Restrict access to sensitive files'
                    })
        
        return self.vulnerabilities
