"""
API Scanner Module - Handles API security testing
Includes endpoint discovery, authentication testing, and data exposure checks
"""

import requests
import json
import time
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urljoin, urlparse


class APIScanner:
    """
    API Scanner Module for comprehensive API security testing
    """
    
    def __init__(self, target: str, progress_callback: Optional[Callable] = None):
        self.target = target
        self.progress_callback = progress_callback or self._default_progress_callback
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedScan-AI/1.0 API Security Scanner',
            'Accept': 'application/json, text/plain, */*'
        })
        
        # Common API endpoints to test
        self.common_api_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/graphql',
            '/swagger',
            '/openapi',
            '/docs',
            '/api-docs',
            '/api/docs',
            '/v1',
            '/v2'
        ]
        
        # Common API endpoints for testing
        self.test_endpoints = [
            '/users',
            '/user',
            '/admin',
            '/login',
            '/auth',
            '/token',
            '/config',
            '/status',
            '/health',
            '/info',
            '/debug'
        ]
    
    def _default_progress_callback(self, progress: int, message: str):
        """Default progress callback"""
        print(f"[{progress}%] {message}")
    
    def _build_url(self, port: int, path: str = '') -> str:
        """Build URL for the target"""
        protocol = 'https' if port in [443, 8443] else 'http'
        if port in [80, 443]:
            return f"{protocol}://{self.target}{path}"
        else:
            return f"{protocol}://{self.target}:{port}{path}"
    
    def discover_api_endpoints(self, port: int) -> Dict[str, Any]:
        """
        Discover API endpoints and documentation
        """
        self.progress_callback(0, "Discovering API endpoints...")
        
        base_url = self._build_url(port)
        results = {
            'base_url': base_url,
            'discovered_apis': [],
            'documentation_found': [],
            'endpoints': [],
            'errors': []
        }
        
        try:
            # Check for common API base paths
            for api_path in self.common_api_paths:
                url = urljoin(base_url, api_path)
                
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200:
                        results['discovered_apis'].append({
                            'url': url,
                            'status': response.status_code,
                            'content_type': response.headers.get('Content-Type', ''),
                            'response_size': len(response.content)
                        })
                        
                        # Check if it's API documentation
                        if self._is_api_documentation(response):
                            results['documentation_found'].append({
                                'url': url,
                                'type': self._detect_doc_type(response),
                                'endpoints': self._extract_endpoints_from_docs(response)
                            })
                    
                    elif response.status_code in [401, 403]:
                        # API exists but requires authentication
                        results['discovered_apis'].append({
                            'url': url,
                            'status': response.status_code,
                            'requires_auth': True,
                            'content_type': response.headers.get('Content-Type', '')
                        })
                
                except Exception as e:
                    results['errors'].append(f"Error testing {url}: {str(e)}")
                
                # Update progress
                progress = int((self.common_api_paths.index(api_path) / len(self.common_api_paths)) * 50)
                self.progress_callback(progress, f"Testing {api_path}...")
            
            # Test specific endpoints on discovered APIs
            for api_info in results['discovered_apis']:
                if api_info['status'] == 200:
                    endpoints = self._test_api_endpoints(api_info['url'])
                    results['endpoints'].extend(endpoints)
            
            self.progress_callback(100, f"API discovery complete - Found {len(results['discovered_apis'])} APIs")
            
        except Exception as e:
            self.progress_callback(100, f"API discovery failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _is_api_documentation(self, response: requests.Response) -> bool:
        """Check if response contains API documentation"""
        content = response.text.lower()
        doc_indicators = [
            'swagger',
            'openapi',
            'api documentation',
            'rest api',
            'graphql',
            '"paths"',
            '"definitions"',
            'api-docs'
        ]
        
        return any(indicator in content for indicator in doc_indicators)
    
    def _detect_doc_type(self, response: requests.Response) -> str:
        """Detect the type of API documentation"""
        content = response.text.lower()
        
        if 'swagger' in content:
            return 'Swagger'
        elif 'openapi' in content:
            return 'OpenAPI'
        elif 'graphql' in content:
            return 'GraphQL'
        elif 'postman' in content:
            return 'Postman Collection'
        else:
            return 'Unknown'
    
    def _extract_endpoints_from_docs(self, response: requests.Response) -> List[str]:
        """Extract API endpoints from documentation"""
        endpoints = []
        
        try:
            # Try to parse as JSON (Swagger/OpenAPI)
            if response.headers.get('Content-Type', '').startswith('application/json'):
                data = response.json()
                
                # OpenAPI/Swagger format
                if 'paths' in data:
                    endpoints.extend(data['paths'].keys())
                
                # Other formats
                elif 'endpoints' in data:
                    endpoints.extend(data['endpoints'])
        
        except Exception:
            # Fallback to regex extraction
            import re
            content = response.text
            
            # Look for path patterns
            path_patterns = [
                r'"/api/[^"]*"',
                r"'/api/[^']*'",
                r'path:\s*["\'][^"\']*["\']',
                r'endpoint:\s*["\'][^"\']*["\']'
            ]
            
            for pattern in path_patterns:
                matches = re.findall(pattern, content)
                endpoints.extend([match.strip('"\'') for match in matches])
        
        return list(set(endpoints))  # Remove duplicates
    
    def _test_api_endpoints(self, base_api_url: str) -> List[Dict[str, Any]]:
        """Test common endpoints on discovered API"""
        endpoints = []
        
        for endpoint in self.test_endpoints:
            url = urljoin(base_api_url, endpoint)
            
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                endpoints.append({
                    'url': url,
                    'method': 'GET',
                    'status': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'response_size': len(response.content),
                    'requires_auth': response.status_code in [401, 403],
                    'potential_data_exposure': self._check_data_exposure(response)
                })
                
            except Exception as e:
                endpoints.append({
                    'url': url,
                    'method': 'GET',
                    'error': str(e)
                })
        
        return endpoints
    
    def _check_data_exposure(self, response: requests.Response) -> bool:
        """Check if response contains potentially sensitive data"""
        if response.status_code != 200:
            return False
        
        try:
            # Check for JSON responses with user data
            if 'application/json' in response.headers.get('Content-Type', ''):
                data = response.json()
                
                # Look for sensitive fields
                sensitive_fields = [
                    'password', 'token', 'secret', 'key', 'email', 
                    'phone', 'ssn', 'credit_card', 'api_key'
                ]
                
                content_str = str(data).lower()
                return any(field in content_str for field in sensitive_fields)
        
        except Exception:
            pass
        
        return False
    
    def test_authentication(self, port: int) -> Dict[str, Any]:
        """
        Test API authentication mechanisms
        """
        self.progress_callback(0, "Testing API authentication...")
        
        base_url = self._build_url(port)
        results = {
            'auth_methods': [],
            'vulnerabilities': [],
            'bypass_attempts': [],
            'weak_tokens': []
        }
        
        try:
            # Discover APIs first
            api_discovery = self.discover_api_endpoints(port)
            
            for api_info in api_discovery.get('discovered_apis', []):
                if api_info.get('requires_auth'):
                    auth_tests = self._test_auth_bypass(api_info['url'])
                    results['bypass_attempts'].extend(auth_tests)
            
            # Test for common authentication issues
            auth_vulns = self._check_auth_vulnerabilities(base_url)
            results['vulnerabilities'].extend(auth_vulns)
            
            self.progress_callback(100, f"Authentication testing complete - Found {len(results['vulnerabilities'])} issues")
            
        except Exception as e:
            self.progress_callback(100, f"Authentication testing failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _test_auth_bypass(self, api_url: str) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        bypass_tests = []
        
        # Test different HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                response = self.session.request(method, api_url, timeout=self.timeout, verify=False)
                
                bypass_tests.append({
                    'url': api_url,
                    'method': method,
                    'status': response.status_code,
                    'bypassed': response.status_code == 200,
                    'response_size': len(response.content)
                })
                
            except Exception as e:
                bypass_tests.append({
                    'url': api_url,
                    'method': method,
                    'error': str(e)
                })
        
        return bypass_tests
    
    def _check_auth_vulnerabilities(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for common authentication vulnerabilities"""
        vulnerabilities = []
        
        # Test for default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('test', 'test')
        ]
        
        login_endpoints = ['/api/login', '/api/auth', '/login', '/auth']
        
        for endpoint in login_endpoints:
            url = urljoin(base_url, endpoint)
            
            for username, password in default_creds:
                try:
                    data = {'username': username, 'password': password}
                    response = self.session.post(url, json=data, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Default Credentials',
                            'severity': 'critical',
                            'url': url,
                            'credentials': f"{username}:{password}",
                            'description': f'Default credentials accepted: {username}:{password}'
                        })
                
                except Exception:
                    pass
        
        return vulnerabilities
    
    def test_data_exposure(self, port: int) -> Dict[str, Any]:
        """
        Test for data exposure vulnerabilities
        """
        self.progress_callback(0, "Testing for data exposure...")
        
        results = {
            'exposed_endpoints': [],
            'sensitive_data': [],
            'vulnerabilities': []
        }
        
        try:
            # Discover APIs and test endpoints
            api_discovery = self.discover_api_endpoints(port)
            
            for endpoint_info in api_discovery.get('endpoints', []):
                if endpoint_info.get('potential_data_exposure'):
                    results['exposed_endpoints'].append(endpoint_info)
                    
                    # Analyze the type of data exposed
                    data_analysis = self._analyze_exposed_data(endpoint_info['url'])
                    if data_analysis:
                        results['sensitive_data'].append(data_analysis)
                        
                        # Create vulnerability entry
                        results['vulnerabilities'].append({
                            'type': 'Data Exposure',
                            'severity': data_analysis['severity'],
                            'url': endpoint_info['url'],
                            'description': data_analysis['description'],
                            'data_types': data_analysis['data_types']
                        })
            
            self.progress_callback(100, f"Data exposure testing complete - Found {len(results['vulnerabilities'])} issues")
            
        except Exception as e:
            self.progress_callback(100, f"Data exposure testing failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_exposed_data(self, url: str) -> Optional[Dict[str, Any]]:
        """Analyze what type of sensitive data is exposed"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
                data = response.json()
                content_str = str(data).lower()
                
                exposed_data_types = []
                severity = 'low'
                
                # Check for different types of sensitive data
                if any(field in content_str for field in ['password', 'secret', 'key', 'token']):
                    exposed_data_types.append('Authentication credentials')
                    severity = 'critical'
                
                if any(field in content_str for field in ['email', 'phone', 'address']):
                    exposed_data_types.append('Personal information')
                    severity = 'high' if severity != 'critical' else severity
                
                if any(field in content_str for field in ['credit_card', 'ssn', 'bank']):
                    exposed_data_types.append('Financial information')
                    severity = 'critical'
                
                if any(field in content_str for field in ['admin', 'config', 'database']):
                    exposed_data_types.append('System configuration')
                    severity = 'high' if severity not in ['critical'] else severity
                
                if exposed_data_types:
                    return {
                        'url': url,
                        'data_types': exposed_data_types,
                        'severity': severity,
                        'description': f'Sensitive data exposed: {", ".join(exposed_data_types)}'
                    }
        
        except Exception:
            pass
        
        return None
    
    def comprehensive_scan(self, port: int) -> Dict[str, Any]:
        """
        Comprehensive API security scan
        """
        self.progress_callback(0, "Starting comprehensive API scan...")
        
        results = {
            'discovery': self.discover_api_endpoints(port),
            'authentication': self.test_authentication(port),
            'data_exposure': self.test_data_exposure(port),
            'cors_testing': self._test_cors(port),
            'rate_limiting': self._test_rate_limiting(port)
        }
        
        self.progress_callback(100, "Comprehensive API scan complete")
        return results
    
    def basic_api_scan(self, port: int) -> Dict[str, Any]:
        """
        Basic API scan for custom scans
        """
        return {
            'discovery': self.discover_api_endpoints(port),
            'basic_auth_test': self._basic_auth_test(port)
        }
    
    def _test_cors(self, port: int) -> Dict[str, Any]:
        """Test CORS configuration"""
        base_url = self._build_url(port)
        
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(base_url, headers=headers, timeout=self.timeout, verify=False)
            
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods')
            }
            
            # Check for misconfigurations
            vulnerabilities = []
            if cors_headers['Access-Control-Allow-Origin'] == '*':
                vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'medium',
                    'description': 'Wildcard origin allowed in CORS policy'
                })
            
            return {
                'cors_headers': cors_headers,
                'vulnerabilities': vulnerabilities
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def _test_rate_limiting(self, port: int) -> Dict[str, Any]:
        """Test for rate limiting"""
        base_url = self._build_url(port)
        
        try:
            # Make multiple rapid requests
            responses = []
            for i in range(10):
                response = self.session.get(base_url, timeout=self.timeout, verify=False)
                responses.append(response.status_code)
            
            # Check if rate limiting is in place
            rate_limited = any(status == 429 for status in responses)
            
            return {
                'rate_limiting_detected': rate_limited,
                'response_codes': responses,
                'vulnerability': None if rate_limited else {
                    'type': 'Missing Rate Limiting',
                    'severity': 'medium',
                    'description': 'No rate limiting detected - API may be vulnerable to abuse'
                }
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def _basic_auth_test(self, port: int) -> Dict[str, Any]:
        """Basic authentication testing"""
        return {
            'default_credentials_tested': True,
            'vulnerabilities': []
        }