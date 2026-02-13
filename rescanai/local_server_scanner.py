import socket
import requests
import time
import os
import re
import subprocess
import platform
from urllib.parse import urljoin, urlparse
from django.conf import settings
import threading
import json
import base64
from pathlib import Path

class ComprehensiveLocalhostScanner:
    """
    Comprehensive localhost scanner covering all local development scenarios
    - Web Development Servers (React, Vue, Angular, Flask, etc.)
    - Local Testing Environments (XAMPP, WAMP, Docker)
    - API Testing (REST, GraphQL)
    - Internal Network Testing
    - Container Testing
    """
    
    def __init__(self, target='localhost', progress_callback=None):
        self.target = target
        self.progress_callback = progress_callback
        self.current_progress = 0
        self.results = {
            'target': target,
            'scan_type': 'Comprehensive Localhost',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'environment_type': 'unknown',
            'services': [],
            'development_servers': [],
            'testing_environments': [],
            'containers': [],
            'apis': [],
            'vulnerabilities': [],
            'exposed_configs': [],
            'default_credentials': [],
            'development_tools': [],
            'recommendations': []
        }
    
    def update_progress(self, increment=1, status="Scanning..."):
        """Update progress by 1% increments"""
        self.current_progress += increment
        if self.current_progress > 100:
            self.current_progress = 100
        if self.progress_callback:
            self.progress_callback(self.current_progress, status)
        time.sleep(0.05)  # Faster updates for localhost
    
    def detect_environment_type(self):
        """Detect the type of localhost environment"""
        self.update_progress(1, "Detecting localhost environment type...")
        
        # Check for common development ports
        dev_ports = {
            3000: 'React/Node.js Development',
            3001: 'React/Node.js Development (Alt)',
            4200: 'Angular Development',
            5000: 'Flask/Python Development',
            5173: 'Vite Development Server',
            8080: 'Spring Boot/Tomcat',
            8000: 'Django Development',
            9000: 'Various Development Servers'
        }
        
        # Check for testing environment ports
        testing_ports = {
            80: 'XAMPP/WAMP Apache',
            443: 'XAMPP/WAMP Apache SSL',
            3306: 'MySQL/MariaDB',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            8080: 'Jenkins/Tomcat Admin'
        }
        
        # Check for container ports
        container_ports = {
            2375: 'Docker API (Insecure)',
            2376: 'Docker API (Secure)',
            8080: 'Container Web Interface',
            9000: 'Portainer'
        }
        
        detected_services = []
        for port, service in {**dev_ports, **testing_ports, **container_ports}.items():
            if self.check_port(port):
                detected_services.append({'port': port, 'service': service})
                self.update_progress(1, f"Found {service} on port {port}")
        
        # Determine primary environment type
        if any(p in [3000, 3001, 4200, 5173] for p in [s['port'] for s in detected_services]):
            self.results['environment_type'] = 'web_development'
        elif any(p in [80, 3306, 8080] for p in [s['port'] for s in detected_services]):
            self.results['environment_type'] = 'testing_environment'
        elif any(p in [2375, 2376, 9000] for p in [s['port'] for s in detected_services]):
            self.results['environment_type'] = 'container_environment'
        else:
            self.results['environment_type'] = 'mixed_environment'
        
        self.results['services'] = detected_services
        return self.results['environment_type']
    
    def check_port(self, port, timeout=1):
        """Quick port check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_web_development_servers(self):
        """Scan for web development servers with 1% increments"""
        self.update_progress(1, "Scanning web development servers...")
        
        dev_servers = [
            {'port': 3000, 'name': 'React/Node.js', 'endpoints': ['/', '/static/', '/api/']},
            {'port': 3001, 'name': 'React Dev (Alt)', 'endpoints': ['/', '/static/', '/api/']},
            {'port': 4200, 'name': 'Angular', 'endpoints': ['/', '/assets/', '/api/']},
            {'port': 5000, 'name': 'Flask', 'endpoints': ['/', '/static/', '/admin/', '/api/']},
            {'port': 5173, 'name': 'Vite', 'endpoints': ['/', '/src/', '/@vite/']},
            {'port': 8080, 'name': 'Spring Boot', 'endpoints': ['/', '/actuator/', '/api/']},
            {'port': 8000, 'name': 'Django', 'endpoints': ['/', '/admin/', '/static/', '/api/']},
            {'port': 9000, 'name': 'Development Server', 'endpoints': ['/', '/api/']}
        ]
        
        for server in dev_servers:
            if self.check_port(server['port']):
                self.update_progress(1, f"Analyzing {server['name']} server...")
                server_info = self.analyze_development_server(server)
                if server_info:
                    self.results['development_servers'].append(server_info)
    
    def analyze_development_server(self, server):
        """Analyze a specific development server"""
        base_url = f"http://{self.target}:{server['port']}"
        server_info = {
            'port': server['port'],
            'name': server['name'],
            'base_url': base_url,
            'framework': 'unknown',
            'debug_mode': False,
            'hot_reload': False,
            'source_maps': False,
            'exposed_endpoints': [],
            'security_issues': []
        }
        
        try:
            # Test main endpoint
            response = requests.get(base_url, timeout=3)
            server_info['status_code'] = response.status_code
            server_info['server_header'] = response.headers.get('Server', 'Unknown')
            
            # Detect framework
            server_info['framework'] = self.detect_development_framework(response)
            
            # Check for debug mode indicators
            if self.check_debug_mode(response):
                server_info['debug_mode'] = True
                server_info['security_issues'].append({
                    'type': 'Debug Mode Enabled',
                    'severity': 'High',
                    'description': 'Development server running in debug mode'
                })
            
            # Check for hot reload
            if self.check_hot_reload(response):
                server_info['hot_reload'] = True
            
            # Check for source maps
            if self.check_source_maps(base_url):
                server_info['source_maps'] = True
                server_info['security_issues'].append({
                    'type': 'Source Maps Exposed',
                    'severity': 'Medium',
                    'description': 'Source maps are accessible, revealing source code structure'
                })
            
            # Test endpoints
            for endpoint in server['endpoints']:
                endpoint_url = urljoin(base_url, endpoint)
                if self.test_endpoint(endpoint_url):
                    server_info['exposed_endpoints'].append(endpoint)
            
            return server_info
            
        except Exception as e:
            return None
    
    def detect_development_framework(self, response):
        """Detect development framework from response"""
        content = response.text.lower()
        headers = response.headers
        
        # React detection
        if 'react' in content or 'webpack' in content:
            return 'React'
        
        # Vue.js detection
        if 'vue' in content or '__vue__' in content:
            return 'Vue.js'
        
        # Angular detection
        if 'angular' in content or 'ng-version' in content:
            return 'Angular'
        
        # Django detection
        if 'django' in headers.get('Server', '').lower() or 'csrftoken' in content:
            return 'Django'
        
        # Flask detection
        if 'werkzeug' in headers.get('Server', '').lower():
            return 'Flask'
        
        # Spring Boot detection
        if 'spring' in content or 'actuator' in content:
            return 'Spring Boot'
        
        # Vite detection
        if 'vite' in content or '@vite' in content:
            return 'Vite'
        
        return 'Unknown'
    
    def check_debug_mode(self, response):
        """Check for debug mode indicators"""
        content = response.text.lower()
        debug_indicators = [
            'debug=true', 'debug mode', 'development mode',
            'webpack-dev-server', 'hot reload', 'livereload',
            'django.core.exceptions', 'traceback', 'stack trace'
        ]
        return any(indicator in content for indicator in debug_indicators)
    
    def check_hot_reload(self, response):
        """Check for hot reload functionality"""
        content = response.text.lower()
        hot_reload_indicators = [
            'hot reload', 'livereload', 'webpack-dev-server',
            'hot-update', 'sockjs', 'websocket'
        ]
        return any(indicator in content for indicator in hot_reload_indicators)
    
    def check_source_maps(self, base_url):
        """Check for exposed source maps"""
        source_map_paths = [
            '/static/js/main.js.map',
            '/js/app.js.map',
            '/dist/main.js.map',
            '/build/static/js/main.js.map'
        ]
        
        for path in source_map_paths:
            try:
                response = requests.get(urljoin(base_url, path), timeout=2)
                if response.status_code == 200 and 'sourceMappingURL' in response.text:
                    return True
            except:
                continue
        return False
    
    def test_endpoint(self, url):
        """Test if an endpoint is accessible"""
        try:
            response = requests.get(url, timeout=2)
            return response.status_code in [200, 301, 302, 403]
        except:
            return False
    
    def scan_testing_environments(self):
        """Scan for local testing environments (XAMPP, WAMP, etc.)"""
        self.update_progress(1, "Scanning testing environments...")
        
        testing_envs = [
            {'port': 80, 'name': 'XAMPP/WAMP Apache', 'paths': ['/phpmyadmin/', '/xampp/', '/dashboard/']},
            {'port': 8080, 'name': 'Jenkins', 'paths': ['/jenkins/', '/login', '/manage']},
            {'port': 3306, 'name': 'MySQL', 'type': 'database'},
            {'port': 5432, 'name': 'PostgreSQL', 'type': 'database'},
            {'port': 6379, 'name': 'Redis', 'type': 'cache'},
            {'port': 27017, 'name': 'MongoDB', 'type': 'database'}
        ]
        
        for env in testing_envs:
            if self.check_port(env['port']):
                self.update_progress(1, f"Analyzing {env['name']}...")
                env_info = self.analyze_testing_environment(env)
                if env_info:
                    self.results['testing_environments'].append(env_info)
    
    def analyze_testing_environment(self, env):
        """Analyze a testing environment"""
        env_info = {
            'port': env['port'],
            'name': env['name'],
            'type': env.get('type', 'web'),
            'accessible_paths': [],
            'default_credentials': [],
            'security_issues': []
        }
        
        if env.get('type') == 'database':
            # Test database connections
            env_info['security_issues'].append({
                'type': 'Database Exposed',
                'severity': 'High',
                'description': f'{env["name"]} database is accessible from localhost'
            })
            
            # Test default credentials
            if self.test_default_db_credentials(env):
                env_info['default_credentials'].append('Default credentials accepted')
                env_info['security_issues'].append({
                    'type': 'Default Credentials',
                    'severity': 'Critical',
                    'description': f'{env["name"]} accepts default credentials'
                })
        
        elif env.get('paths'):
            # Test web paths
            base_url = f"http://{self.target}:{env['port']}"
            for path in env['paths']:
                test_url = urljoin(base_url, path)
                if self.test_endpoint(test_url):
                    env_info['accessible_paths'].append(path)
                    
                    # Check for admin interfaces
                    if any(admin_term in path.lower() for admin_term in ['admin', 'manage', 'phpmyadmin']):
                        env_info['security_issues'].append({
                            'type': 'Admin Interface Exposed',
                            'severity': 'High',
                            'description': f'Admin interface accessible at {path}'
                        })
        
        return env_info if env_info['accessible_paths'] or env_info['security_issues'] else None
    
    def test_default_db_credentials(self, env):
        """Test default database credentials"""
        # This is a simplified check - in practice, you'd use proper database clients
        default_creds = {
            'MySQL': [('root', ''), ('root', 'root'), ('admin', 'admin')],
            'PostgreSQL': [('postgres', ''), ('postgres', 'postgres')],
            'MongoDB': [('admin', ''), ('root', 'root')],
            'Redis': [(None, None)]  # Redis often has no auth
        }
        
        # Simplified check - would need proper implementation
        return False  # Placeholder
    
    def scan_api_endpoints(self):
        """Scan for API endpoints with 1% increments"""
        self.update_progress(1, "Scanning API endpoints...")
        
        api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql/',
            '/swagger/', '/docs/', '/openapi.json', '/api-docs/',
            '/health/', '/status/', '/metrics/', '/actuator/'
        ]
        
        common_ports = [3000, 5000, 8000, 8080, 9000]
        
        for port in common_ports:
            if self.check_port(port):
                self.update_progress(1, f"Testing API endpoints on port {port}...")
                base_url = f"http://{self.target}:{port}"
                
                api_info = {
                    'port': port,
                    'base_url': base_url,
                    'endpoints': [],
                    'documentation': [],
                    'security_issues': []
                }
                
                for path in api_paths:
                    test_url = urljoin(base_url, path)
                    if self.test_api_endpoint(test_url):
                        api_info['endpoints'].append(path)
                        
                        # Check for documentation exposure
                        if any(doc_term in path for doc_term in ['swagger', 'docs', 'openapi']):
                            api_info['documentation'].append(path)
                            api_info['security_issues'].append({
                                'type': 'API Documentation Exposed',
                                'severity': 'Medium',
                                'description': f'API documentation accessible at {path}'
                            })
                
                if api_info['endpoints']:
                    self.results['apis'].append(api_info)
    
    def test_api_endpoint(self, url):
        """Test API endpoint with various methods"""
        try:
            # Test GET request
            response = requests.get(url, timeout=2)
            if response.status_code in [200, 401, 403]:
                return True
            
            # Test OPTIONS for CORS
            options_response = requests.options(url, timeout=2)
            if options_response.status_code == 200:
                return True
                
        except:
            pass
        return False
    
    def scan_container_environments(self):
        """Scan for Docker and container environments"""
        self.update_progress(1, "Scanning container environments...")
        
        container_ports = [
            {'port': 2375, 'name': 'Docker API (Insecure)', 'risk': 'Critical'},
            {'port': 2376, 'name': 'Docker API (Secure)', 'risk': 'High'},
            {'port': 9000, 'name': 'Portainer', 'risk': 'Medium'},
            {'port': 8080, 'name': 'Container Web UI', 'risk': 'Medium'}
        ]
        
        for container in container_ports:
            if self.check_port(container['port']):
                self.update_progress(1, f"Analyzing {container['name']}...")
                
                container_info = {
                    'port': container['port'],
                    'name': container['name'],
                    'risk_level': container['risk'],
                    'accessible': True,
                    'security_issues': []
                }
                
                # Docker API specific checks
                if container['port'] in [2375, 2376]:
                    container_info['security_issues'].append({
                        'type': 'Docker API Exposed',
                        'severity': container['risk'].lower(),
                        'description': f'Docker API accessible on port {container["port"]}'
                    })
                
                self.results['containers'].append(container_info)
    
    def check_exposed_configurations(self):
        """Check for exposed configuration files"""
        self.update_progress(1, "Checking for exposed configurations...")
        
        config_paths = [
            '/.env', '/config.json', '/settings.json', '/app.config',
            '/.git/config', '/package.json', '/composer.json',
            '/web.config', '/.htaccess', '/robots.txt', '/sitemap.xml'
        ]
        
        common_ports = [80, 3000, 5000, 8000, 8080]
        
        for port in common_ports:
            if self.check_port(port):
                base_url = f"http://{self.target}:{port}"
                
                for config_path in config_paths:
                    self.update_progress(1, f"Checking {config_path} on port {port}...")
                    config_url = urljoin(base_url, config_path)
                    
                    try:
                        response = requests.get(config_url, timeout=2)
                        if response.status_code == 200:
                            self.results['exposed_configs'].append({
                                'port': port,
                                'path': config_path,
                                'url': config_url,
                                'size': len(response.content),
                                'content_preview': response.text[:200]
                            })
                    except:
                        continue
    
    def check_development_tools(self):
        """Check for exposed development tools"""
        self.update_progress(1, "Checking development tools...")
        
        dev_tools = [
            {'path': '/webpack-dev-server/', 'name': 'Webpack Dev Server'},
            {'path': '/__webpack_hmr', 'name': 'Webpack HMR'},
            {'path': '/livereload.js', 'name': 'LiveReload'},
            {'path': '/browser-sync/', 'name': 'BrowserSync'},
            {'path': '/_next/', 'name': 'Next.js Dev'},
            {'path': '/@vite/', 'name': 'Vite Dev Tools'}
        ]
        
        common_ports = [3000, 3001, 4200, 5173, 8080]
        
        for port in common_ports:
            if self.check_port(port):
                base_url = f"http://{self.target}:{port}"
                
                for tool in dev_tools:
                    tool_url = urljoin(base_url, tool['path'])
                    if self.test_endpoint(tool_url):
                        self.results['development_tools'].append({
                            'port': port,
                            'name': tool['name'],
                            'path': tool['path'],
                            'url': tool_url
                        })
    
    def generate_comprehensive_recommendations(self):
        """Generate comprehensive security recommendations"""
        self.update_progress(1, "Generating security recommendations...")
        
        recommendations = []
        
        # Development server recommendations
        if self.results['development_servers']:
            for server in self.results['development_servers']:
                if server.get('debug_mode'):
                    recommendations.append({
                        'priority': 'High',
                        'category': 'Development Security',
                        'action': f'Disable debug mode on {server["name"]}',
                        'description': 'Debug mode exposes sensitive information and should be disabled'
                    })
                
                if server.get('source_maps'):
                    recommendations.append({
                        'priority': 'Medium',
                        'category': 'Information Disclosure',
                        'action': f'Remove source maps from {server["name"]}',
                        'description': 'Source maps reveal application structure and should not be accessible'
                    })
        
        # Testing environment recommendations
        if self.results['testing_environments']:
            recommendations.append({
                'priority': 'High',
                'category': 'Testing Environment',
                'action': 'Secure testing environment access',
                'description': 'Restrict access to testing tools and admin interfaces'
            })
        
        # Container recommendations
        if self.results['containers']:
            for container in self.results['containers']:
                if container['port'] == 2375:
                    recommendations.append({
                        'priority': 'Critical',
                        'category': 'Container Security',
                        'action': 'Secure Docker API',
                        'description': 'Docker API is exposed without authentication - immediate security risk'
                    })
        
        # Configuration exposure recommendations
        if self.results['exposed_configs']:
            recommendations.append({
                'priority': 'High',
                'category': 'Configuration Security',
                'action': 'Protect configuration files',
                'description': 'Configuration files are exposed and may contain sensitive information'
            })
        
        # General localhost recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'category': 'Network Security',
                'action': 'Implement network segmentation',
                'description': 'Isolate development and testing environments from production networks'
            },
            {
                'priority': 'Medium',
                'category': 'Access Control',
                'action': 'Use authentication for all services',
                'description': 'Implement proper authentication even in development environments'
            },
            {
                'priority': 'Low',
                'category': 'Monitoring',
                'action': 'Monitor localhost services',
                'description': 'Regularly audit and monitor services running on localhost'
            }
        ])
        
        self.results['recommendations'] = recommendations
    
    def run_comprehensive_scan(self):
        """Run comprehensive localhost scan with 1% increments"""
        self.update_progress(0, "Starting comprehensive localhost scan...")
        
        # Phase 1: Environment Detection (1-10%)
        self.update_progress(1, "Initializing localhost scanner...")
        env_type = self.detect_environment_type()
        self.update_progress(2, f"Detected environment: {env_type}")
        
        # Phase 2: Web Development Servers (11-30%)
        self.update_progress(1, "Scanning web development servers...")
        self.scan_web_development_servers()
        
        # Phase 3: Testing Environments (31-50%)
        self.update_progress(1, "Scanning testing environments...")
        self.scan_testing_environments()
        
        # Phase 4: API Endpoints (51-65%)
        self.update_progress(1, "Scanning API endpoints...")
        self.scan_api_endpoints()
        
        # Phase 5: Container Environments (66-75%)
        self.update_progress(1, "Scanning container environments...")
        self.scan_container_environments()
        
        # Phase 6: Configuration Files (76-85%)
        self.update_progress(1, "Checking exposed configurations...")
        self.check_exposed_configurations()
        
        # Phase 7: Development Tools (86-95%)
        self.update_progress(1, "Checking development tools...")
        self.check_development_tools()
        
        # Phase 8: Generate Recommendations (96-100%)
        self.update_progress(1, "Analyzing security posture...")
        self.generate_comprehensive_recommendations()
        
        self.update_progress(4, "Comprehensive localhost scan completed!")
        
        return self.results


class LocalServerScanner:
    """
    Comprehensive localhost/local server scanner with Django-specific testing
    Features 1% increment progress tracking for detailed scanning
    """
    
    def __init__(self, target='localhost', progress_callback=None):
        self.target = target
        self.progress_callback = progress_callback
        self.results = {
            'target': target,
            'scan_type': 'Local Server',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'ports': [],
            'services': [],
            'django_info': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        self.current_progress = 0
        
    def update_progress(self, increment=1, status="Scanning..."):
        """Update progress by 1% increments"""
        self.current_progress += increment
        if self.current_progress > 100:
            self.current_progress = 100
        if self.progress_callback:
            self.progress_callback(self.current_progress, status)
        time.sleep(0.1)  # Small delay for smooth progress
    
    def scan_localhost_ports(self):
        """Scan common localhost development ports with 1% increments"""
        common_ports = [
            8000, 8080, 3000, 5000, 8001, 8002, 8003, 8004, 8005,
            9000, 9001, 4000, 4200, 5173, 3001, 8888, 7000, 6000
        ]
        
        for i, port in enumerate(common_ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    service_info = self.detect_service(port)
                    self.results['ports'].append({
                        'port': port,
                        'status': 'open',
                        'service': service_info
                    })
                    self.update_progress(1, f"Found service on port {port}")
                else:
                    self.update_progress(1, f"Checking port {port}")
                    
                sock.close()
            except Exception as e:
                self.update_progress(1, f"Error checking port {port}")
                
    def detect_service(self, port):
        """Detect service running on specific port"""
        try:
            response = requests.get(f'http://{self.target}:{port}', timeout=3)
            server_header = response.headers.get('Server', 'Unknown')
            
            service_info = {
                'type': 'HTTP',
                'server': server_header,
                'status_code': response.status_code,
                'framework': self.detect_framework(response)
            }
            
            self.results['services'].append(service_info)
            return service_info
            
        except Exception as e:
            return {'type': 'Unknown', 'error': str(e)}
    
    def detect_framework(self, response):
        """Detect web framework from response"""
        headers = response.headers
        content = response.text.lower()
        
        # Django detection
        if 'django' in headers.get('Server', '').lower():
            return 'Django'
        if 'csrftoken' in content or 'django' in content:
            return 'Django'
        if 'x-frame-options' in headers and 'sameorigin' in headers.get('x-frame-options', '').lower():
            return 'Likely Django'
            
        # Other frameworks
        if 'express' in headers.get('x-powered-by', '').lower():
            return 'Express.js'
        if 'react' in content:
            return 'React'
        if 'vue' in content:
            return 'Vue.js'
        if 'angular' in content:
            return 'Angular'
            
        return 'Unknown'
    
    def scan_django_specifics(self, port=8000):
        """Django-specific scanning with detailed progress"""
        base_url = f'http://{self.target}:{port}'
        
        # Check if Django is running
        self.update_progress(1, "Checking Django server...")
        try:
            response = requests.get(base_url, timeout=5)
            if response.status_code == 200:
                self.results['django_info']['server_running'] = True
                self.update_progress(1, "Django server detected")
            else:
                self.results['django_info']['server_running'] = False
                self.update_progress(1, "No Django server found")
                return
        except:
            self.results['django_info']['server_running'] = False
            self.update_progress(1, "Django server not accessible")
            return
        
        # Check admin panel
        self.update_progress(1, "Checking admin panel...")
        admin_urls = ['/admin/', '/admin/login/', '/django-admin/']
        for admin_url in admin_urls:
            try:
                admin_response = requests.get(urljoin(base_url, admin_url), timeout=3)
                if admin_response.status_code == 200:
                    self.results['django_info']['admin_accessible'] = True
                    self.results['django_info']['admin_url'] = admin_url
                    self.update_progress(1, f"Admin panel found at {admin_url}")
                    break
            except:
                continue
        else:
            self.results['django_info']['admin_accessible'] = False
            self.update_progress(1, "Admin panel not found")
        
        # Check debug mode
        self.update_progress(1, "Checking debug mode...")
        try:
            # Try to trigger a 404 to see debug info
            debug_response = requests.get(urljoin(base_url, '/nonexistent-page-test-debug'), timeout=3)
            if 'django.core.exceptions' in debug_response.text.lower() or 'debug' in debug_response.text.lower():
                self.results['django_info']['debug_mode'] = True
                self.results['vulnerabilities'].append({
                    'type': 'Debug Mode Enabled',
                    'severity': 'High',
                    'description': 'Django debug mode is enabled, exposing sensitive information'
                })
                self.update_progress(1, "Debug mode detected (HIGH RISK)")
            else:
                self.results['django_info']['debug_mode'] = False
                self.update_progress(1, "Debug mode appears disabled")
        except:
            self.update_progress(1, "Could not determine debug mode")
        
        # Check static files
        self.update_progress(1, "Checking static files...")
        static_urls = ['/static/', '/media/', '/assets/']
        for static_url in static_urls:
            try:
                static_response = requests.get(urljoin(base_url, static_url), timeout=3)
                if static_response.status_code in [200, 403]:  # 403 means directory exists but listing disabled
                    self.results['django_info']['static_files'] = True
                    self.update_progress(1, f"Static files accessible at {static_url}")
                    break
            except:
                continue
        else:
            self.results['django_info']['static_files'] = False
            self.update_progress(1, "Static files not accessible")
        
        # Check common Django URLs
        self.update_progress(1, "Checking common Django endpoints...")
        common_urls = ['/', '/api/', '/accounts/', '/login/', '/logout/', '/register/']
        accessible_urls = []
        
        for url in common_urls:
            try:
                url_response = requests.get(urljoin(base_url, url), timeout=3)
                if url_response.status_code == 200:
                    accessible_urls.append(url)
                self.update_progress(1, f"Checked {url}")
            except:
                self.update_progress(1, f"Error checking {url}")
        
        self.results['django_info']['accessible_urls'] = accessible_urls
    
    def check_security_headers(self, port=8000):
        """Check security headers with progress tracking"""
        base_url = f'http://{self.target}:{port}'
        
        try:
            response = requests.get(base_url, timeout=5)
            headers = response.headers
            
            security_checks = [
                ('X-Frame-Options', 'Clickjacking protection'),
                ('X-Content-Type-Options', 'MIME type sniffing protection'),
                ('X-XSS-Protection', 'XSS protection'),
                ('Strict-Transport-Security', 'HTTPS enforcement'),
                ('Content-Security-Policy', 'Content security policy'),
                ('Referrer-Policy', 'Referrer policy'),
                ('Permissions-Policy', 'Permissions policy')
            ]
            
            missing_headers = []
            for header, description in security_checks:
                if header not in headers:
                    missing_headers.append({
                        'header': header,
                        'description': description
                    })
                self.update_progress(1, f"Checking {header}")
            
            if missing_headers:
                self.results['vulnerabilities'].append({
                    'type': 'Missing Security Headers',
                    'severity': 'Medium',
                    'description': f'Missing {len(missing_headers)} security headers',
                    'details': missing_headers
                })
                
        except Exception as e:
            self.update_progress(7, "Error checking security headers")
    
    def check_django_settings(self):
        """Check Django settings for security issues"""
        security_issues = []
        
        # Check SECRET_KEY
        self.update_progress(1, "Checking SECRET_KEY...")
        try:
            if hasattr(settings, 'SECRET_KEY'):
                if settings.SECRET_KEY == 'django-insecure-' or len(settings.SECRET_KEY) < 50:
                    security_issues.append({
                        'setting': 'SECRET_KEY',
                        'issue': 'Weak or default secret key'
                    })
        except:
            pass
        
        # Check DEBUG setting
        self.update_progress(1, "Checking DEBUG setting...")
        try:
            if hasattr(settings, 'DEBUG') and settings.DEBUG:
                security_issues.append({
                    'setting': 'DEBUG',
                    'issue': 'Debug mode enabled in production'
                })
        except:
            pass
        
        # Check ALLOWED_HOSTS
        self.update_progress(1, "Checking ALLOWED_HOSTS...")
        try:
            if hasattr(settings, 'ALLOWED_HOSTS'):
                if '*' in settings.ALLOWED_HOSTS:
                    security_issues.append({
                        'setting': 'ALLOWED_HOSTS',
                        'issue': 'Wildcard in ALLOWED_HOSTS'
                    })
        except:
            pass
        
        # Check database configuration
        self.update_progress(1, "Checking database config...")
        try:
            if hasattr(settings, 'DATABASES'):
                for db_name, db_config in settings.DATABASES.items():
                    if db_config.get('ENGINE') == 'django.db.backends.sqlite3':
                        if 'PASSWORD' not in db_config or not db_config.get('PASSWORD'):
                            security_issues.append({
                                'setting': f'DATABASES.{db_name}',
                                'issue': 'Database without password protection'
                            })
        except:
            pass
        
        if security_issues:
            self.results['vulnerabilities'].append({
                'type': 'Django Configuration Issues',
                'severity': 'High',
                'description': f'Found {len(security_issues)} configuration issues',
                'details': security_issues
            })
        
        self.update_progress(1, "Django settings check complete")
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        # Based on found vulnerabilities
        for vuln in self.results['vulnerabilities']:
            if vuln['type'] == 'Debug Mode Enabled':
                recommendations.append({
                    'priority': 'High',
                    'action': 'Disable DEBUG mode',
                    'description': 'Set DEBUG = False in settings.py for production'
                })
            
            if vuln['type'] == 'Missing Security Headers':
                recommendations.append({
                    'priority': 'Medium',
                    'action': 'Add security headers',
                    'description': 'Implement missing security headers using django-security middleware'
                })
            
            if vuln['type'] == 'Django Configuration Issues':
                recommendations.append({
                    'priority': 'High',
                    'action': 'Fix configuration issues',
                    'description': 'Review and fix Django settings for security best practices'
                })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'action': 'Enable HTTPS',
                'description': 'Use HTTPS in production with proper SSL certificates'
            },
            {
                'priority': 'Low',
                'action': 'Regular security updates',
                'description': 'Keep Django and dependencies updated to latest versions'
            },
            {
                'priority': 'Medium',
                'action': 'Implement rate limiting',
                'description': 'Add rate limiting to prevent abuse and DoS attacks'
            }
        ])
        
        self.results['recommendations'] = recommendations
        self.update_progress(5, "Recommendations generated")
    
    def run_full_scan(self):
        """Run complete localhost/local server scan with 1% increments"""
        self.update_progress(0, "Starting localhost scan...")
        
        # Phase 1: Port scanning (18% total)
        self.update_progress(1, "Initializing port scan...")
        self.scan_localhost_ports()
        
        # Phase 2: Django-specific scanning (25% total)
        self.update_progress(1, "Starting Django analysis...")
        self.scan_django_specifics()
        
        # Phase 3: Security headers check (7% total)
        self.update_progress(1, "Analyzing security headers...")
        self.check_security_headers()
        
        # Phase 4: Django settings check (5% total)
        self.update_progress(1, "Checking Django configuration...")
        self.check_django_settings()
        
        # Phase 5: Generate recommendations (5% total)
        self.update_progress(1, "Generating recommendations...")
        self.generate_recommendations()
        
        # Complete scan
        self.update_progress(1, "Scan completed successfully!")
        
        return self.results

class DjangoSecurityAnalyzer:
    """
    Specialized Django security analyzer for local development
    """
    
    def __init__(self, project_path='.'):
        self.project_path = project_path
        self.security_issues = []
        
    def analyze_settings_file(self):
        """Analyze Django settings.py file for security issues"""
        settings_files = ['settings.py', 'settings/local.py', 'settings/development.py']
        
        for settings_file in settings_files:
            settings_path = os.path.join(self.project_path, settings_file)
            if os.path.exists(settings_path):
                with open(settings_path, 'r') as f:
                    content = f.read()
                    
                # Check for common security issues
                if 'DEBUG = True' in content:
                    self.security_issues.append({
                        'file': settings_file,
                        'issue': 'DEBUG mode enabled',
                        'severity': 'High'
                    })
                
                if "SECRET_KEY = 'django-insecure-" in content:
                    self.security_issues.append({
                        'file': settings_file,
                        'issue': 'Default insecure SECRET_KEY',
                        'severity': 'Critical'
                    })
                
                if "ALLOWED_HOSTS = ['*']" in content or 'ALLOWED_HOSTS = ["*"]' in content:
                    self.security_issues.append({
                        'file': settings_file,
                        'issue': 'Wildcard in ALLOWED_HOSTS',
                        'severity': 'High'
                    })
        
        return self.security_issues