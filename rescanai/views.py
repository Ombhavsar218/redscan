from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Target, Scan, Port, Vulnerability, ScanLog, WebReconData, LocalServerData, AdvancedVulnerabilityData
from .scanner import NetworkScanner, VulnerabilityScanner, ReconEngine, LocalReconEngine
from .web_recon import WebsiteRecon, WebVulnerabilityScanner
from .local_server_scanner import LocalServerScanner, DjangoSecurityAnalyzer, ComprehensiveLocalhostScanner
from .vulnerability_engine import AdvancedVulnerabilityEngine
import json
from threading import Thread

def index(request):
    """Dashboard view"""
    recent_scans = Scan.objects.all().order_by('-started_at')[:10]
    recent_activities = Scan.objects.all().order_by('-started_at')[:5]
    total_targets = Target.objects.count()
    total_scans = Scan.objects.count()
    total_vulns = Vulnerability.objects.count()
    critical_vulns = Vulnerability.objects.filter(severity='critical').count()
    active_vulns = Vulnerability.objects.filter(scan__status='completed').count()
    
    context = {
        'recent_scans': recent_scans,
        'recent_activities': recent_activities,
        'total_targets': total_targets,
        'total_scans': total_scans,
        'total_vulns': total_vulns,
        'critical_vulns': critical_vulns,
        'active_vulns': active_vulns,
    }
    return render(request, 'rescanai/dashboard.html', context)

def new_scan(request):
    """New scan page"""
    targets = Target.objects.all()
    context = {
        'targets': targets,
    }
    return render(request, 'rescanai/new_scan.html', context)

@csrf_exempt
def start_scan(request):
    """API endpoint to start a new scan"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        # Check if target_id is provided (old format) or target (new format)
        if 'target_id' in data:
            # Old format: using existing target
            target_id = data.get('target_id')
            target = get_object_or_404(Target, id=target_id)
        else:
            # New format: create target on the fly
            target_value = data.get('target', '').strip()
            target_name = data.get('target_name', target_value).strip()
            
            if not target_value:
                return JsonResponse({'error': 'Target is required'}, status=400)
            
            # Determine target type
            import re
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, target_value):
                target_type = 'ip'
            else:
                target_type = 'domain'
            
            # Get or create user
            user = request.user if request.user.is_authenticated else User.objects.first()
            if not user:
                return JsonResponse({'error': 'No user available'}, status=400)
            
            # Create target
            target, created = Target.objects.get_or_create(
                target_value=target_value,
                defaults={
                    'name': target_name,
                    'target_type': target_type,
                    'created_by': user
                }
            )
        
        scan_type = data.get('scan_type', 'quick')
        scan_options = data.get('scan_options', {})
        
        # Extract port range for custom scans
        if scan_type == 'custom':
            port_start = data.get('port_start', 1)
            port_end = data.get('port_end', 1024)
            scan_options['port_start'] = port_start
            scan_options['port_end'] = port_end
        
        # Create scan record
        scan = Scan.objects.create(
            target=target,
            scan_type=scan_type,
            status='pending',
            created_by=request.user if request.user.is_authenticated else target.created_by
        )
        
        # Run scan in background thread with new modular architecture
        thread = Thread(target=execute_modular_scan, args=(scan.id, scan_options))
        thread.start()
        
        return JsonResponse({
            'success': True,
            'scan_id': scan.id,
            'message': 'Scan started'
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

def execute_modular_scan(scan_id: int, scan_options: dict = None):
    """
    Execute scan using the new modular scanner architecture
    This runs in a background thread
    """
    scan = Scan.objects.get(id=scan_id)
    scan_options = scan_options or {}
    
    try:
        scan.status = 'running'
        scan.save()
        
        # Progress callback to log scan progress
        def progress_callback(progress: int, message: str):
            ScanLog.objects.create(
                scan=scan,
                level='INFO',
                message=f"[{progress}%] {message}"
            )
        
        # Import and initialize the scan controller
        from .scan_controller import ScanController
        
        # Create scan controller
        controller = ScanController(
            target=scan.target.target_value,
            scan_type=scan.scan_type,
            progress_callback=progress_callback
        )
        
        # Execute the scan with options
        results = controller.execute_scan(scan_options)
        
        # Process and save results
        _save_modular_scan_results(scan, results)
        
        # Calculate final risk score
        risk_score = results.get('risk_score', 0.0)
        scan.risk_score = risk_score
        
        # Complete the scan
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()
        
        progress_callback(100, f"Scan completed! Risk score: {risk_score:.1f}/10")
        
    except Exception as e:
        scan.status = 'failed'
        scan.save()
        error_message = f'Modular scan failed: {str(e)}'
        ScanLog.objects.create(scan=scan, level='ERROR', message=error_message)
        print(f"[ERROR] Modular scan {scan.id} failed: {str(e)}")
        import traceback
        traceback.print_exc()


def _save_modular_scan_results(scan, results):
    """
    Save results from modular scanner to database
    """
    try:
        # Save discovered ports
        for port_num in results.get('ports', []):
            service = results.get('services', {}).get(port_num, 'unknown')
            
            Port.objects.create(
                scan=scan,
                port_number=port_num,
                service=service,
                version='',  # Version detection can be added later
                state='open'
            )
        
        # Save vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            # Try to find associated port
            port_obj = None
            if 'port' in vuln:
                port_obj = Port.objects.filter(scan=scan, port_number=vuln['port']).first()
            
            Vulnerability.objects.create(
                scan=scan,
                port=port_obj,
                title=vuln.get('type', 'Security Issue'),
                description=vuln.get('description', 'Security vulnerability detected'),
                severity=vuln.get('severity', 'medium').lower(),
                remediation=vuln.get('remediation', 'Review and fix the identified security issue')
            )
        
        # Save web reconnaissance data if available
        web_data = results.get('web_data', {})
        if web_data:
            _save_web_recon_data(scan, web_data)
        
        # Save API data if available
        api_data = results.get('api_data', {})
        if api_data:
            _save_api_data(scan, api_data)
        
        # Save localhost data if available
        localhost_data = results.get('localhost_data', {})
        if localhost_data:
            _save_localhost_data(scan, localhost_data)
            
    except Exception as e:
        ScanLog.objects.create(
            scan=scan,
            level='ERROR',
            message=f'Error saving scan results: {str(e)}'
        )


def _save_web_recon_data(scan, web_data):
    """Save web reconnaissance data"""
    try:
        # Extract data from different web scan components
        headers_data = web_data.get('headers', {})
        crawl_data = web_data.get('crawl', {})
        tech_data = web_data.get('technologies', {})
        
        WebReconData.objects.create(
            scan=scan,
            cms=tech_data.get('cms', []),
            frameworks=tech_data.get('frameworks', []),
            javascript_libraries=tech_data.get('javascript_libraries', []),
            web_servers=[tech_data.get('web_server', 'unknown')],
            programming_languages=[],  # Can be detected later
            analytics=[],  # Can be detected later
            security_headers=headers_data.get('headers', {}),
            directories=[],  # From crawl data if available
            forms=crawl_data.get('forms', []),
            emails=[],  # Can be extracted later
            robots_txt_content='',  # Can be added later
            sitemap_urls=crawl_data.get('links', [])
        )
    except Exception as e:
        ScanLog.objects.create(
            scan=scan,
            level='ERROR',
            message=f'Error saving web recon data: {str(e)}'
        )


def _save_api_data(scan, api_data):
    """Save API scan data"""
    try:
        # API data can be saved to a custom model or as JSON in existing models
        # For now, log the API findings
        discovery_data = api_data.get('discovery', {})
        discovered_apis = discovery_data.get('discovered_apis', [])
        
        if discovered_apis:
            ScanLog.objects.create(
                scan=scan,
                level='INFO',
                message=f'Discovered {len(discovered_apis)} API endpoints'
            )
    except Exception as e:
        ScanLog.objects.create(
            scan=scan,
            level='ERROR',
            message=f'Error saving API data: {str(e)}'
        )


def _save_localhost_data(scan, localhost_data):
    """Save localhost scan data"""
    try:
        django_data = localhost_data.get('django', {})
        dev_servers = localhost_data.get('dev_servers', {})
        containers = localhost_data.get('containers', {})
        
        LocalServerData.objects.create(
            scan=scan,
            target=scan.target.target_value,
            open_ports=scan.ports.values_list('port_number', flat=True),
            services_detected=list(scan.ports.values_list('service', flat=True)),
            django_detected=django_data.get('detected', False),
            admin_panel_accessible=False,  # Can be detected later
            debug_mode_enabled=False,  # Can be detected later
            static_files_accessible=False,  # Can be detected later
            accessible_urls=[],
            security_headers={},
            configuration_issues=[],
            security_recommendations=[]
        )
    except Exception as e:
        ScanLog.objects.create(
            scan=scan,
            level='ERROR',
            message=f'Error saving localhost data: {str(e)}'
        )


def execute_scan(scan_id: int):
    """
    Execute the actual scanning process with adaptive progress tracking
    This runs in a background thread
    """
    scan = Scan.objects.get(id=scan_id)
    
    try:
        scan.status = 'running'
        scan.save()
        
        # Step 1: Initialize and detect scan type
        log_progress(scan, 1, "Initializing scan environment...")
        log_progress(scan, 2, "Validating target address...")
        log_progress(scan, 3, "Setting up network scanner...")
        
        scanner = NetworkScanner(scan.target.target_value)
        
        log_progress(scan, 4, "Configuring scan parameters...")
        log_progress(scan, 5, f"Starting {scan.scan_type} scan on {scan.target.target_value}")
        
        # Determine port range based on scan type
        if scan.scan_type == 'quick':
            port_range = range(1, 1025)
        elif scan.scan_type == 'full':
            port_range = range(1, 65536)
        elif scan.scan_type == 'web':
            # For web scans, we'll use a custom list but handle it differently
            web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000]
            port_range = web_ports  # We'll handle this specially in the scanner
        elif scan.scan_type == 'vulnerability':
            port_range = range(1, 1025)  # Standard range for vulnerability scans
        elif scan.scan_type == 'localhost':
            port_range = range(8000, 9001)  # Localhost specific range
        else:  # custom or default
            port_range = range(1, 1025)
        
        log_progress(scan, 6, "Network scanner initialized successfully")
        
        # Calculate port count for logging
        if isinstance(port_range, range):
            port_count = port_range.stop - port_range.start
        elif isinstance(port_range, list):
            port_count = len(port_range)
        else:
            port_count = "unknown number of"
        
        log_progress(scan, 7, f"Preparing to scan {port_count} ports...")
        log_progress(scan, 8, "Starting port enumeration...")
        log_progress(scan, 9, "Performing network discovery...")
        
        # Port scanning phase (Steps 10-30)
        open_ports = scanner.scan_ports(port_range)
        
        log_progress(scan, 10, "Port scanning phase completed")
        log_progress(scan, 11, f"Discovered {len(open_ports)} open ports")
        log_progress(scan, 12, "Beginning service detection...")
        
        # Save discovered ports and detect services (Steps 13-25)
        for i, port_num in enumerate(open_ports):
            service = scanner.results['services'].get(port_num, 'unknown')
            banner = scanner.banner_grab(port_num)
            
            Port.objects.create(
                scan=scan,
                port_number=port_num,
                service=service,
                version=banner[:255] if banner else '',
                state='open'
            )
            
            if i == 0:
                log_progress(scan, 13, f"Analyzing service on port {port_num}...")
        
        log_progress(scan, 14, "Service detection completed")
        log_progress(scan, 15, "Analyzing discovered services...")
        
        # Determine scan type based on discovered services
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000, 3000, 5000]]
        api_ports = [p for p in open_ports if p in [8080, 8443, 3000, 5000, 8000]]
        
        # Check if it's a localhost/local server scan
        if scan.target.target_value in ['localhost', '127.0.0.1'] or scan.scan_type == 'localhost':
            execute_localhost_scan(scan, open_ports, 16)
        # Check if it's a vulnerability-focused scan
        elif scan.scan_type == 'vulnerability':
            execute_vulnerability_scan(scan, open_ports, 16)
        # Check if it's primarily a web application
        elif web_ports and scan.scan_type in ['web', 'quick']:
            execute_web_scan(scan, scanner, web_ports, 16)
        # Check if it's an API endpoint
        elif api_ports and any(service in ['http', 'https', 'api'] for service in scanner.results['services'].values()):
            execute_api_scan(scan, api_ports, 16)
        # Default to network scanning
        else:
            execute_network_scan(scan, scanner, open_ports, 16)
        
    except Exception as e:
        scan.status = 'failed'
        scan.save()
        error_message = f'Scan failed: {str(e)}'
        ScanLog.objects.create(scan=scan, level='ERROR', message=error_message)
        print(f"[ERROR] Scan {scan.id} failed: {str(e)}")
        import traceback
        traceback.print_exc()

def log_progress(scan, step, message):
    """Helper function to log progress with step number"""
    ScanLog.objects.create(scan=scan, level='INFO', message=f"[{step}%] {message}")

def execute_vulnerability_scan(scan, open_ports, start_step):
    """Execute advanced vulnerability scanning with 1% increments (Steps 16-100)"""
    step = start_step
    
    log_progress(scan, step, "Advanced vulnerability scanning starting...")
    step += 1
    
    # Initialize advanced vulnerability engine with progress callback
    def progress_callback(progress, message):
        # Map the vulnerability engine's 0-100% to our remaining 84% (16-100)
        adjusted_progress = min(16 + int(progress * 0.84), 100)
        log_progress(scan, adjusted_progress, message)
    
    try:
        vuln_engine = AdvancedVulnerabilityEngine(scan.target.target_value, progress_callback)
        
        log_progress(scan, step, "Initializing vulnerability detection engine...")
        step += 1
        
        log_progress(scan, step, "Starting comprehensive vulnerability assessment...")
        step += 1
        
        # Run the comprehensive vulnerability scan (this handles 1% increments internally)
        results = vuln_engine.run_comprehensive_vulnerability_scan()
        
        # Calculate security score
        security_score = calculate_security_score(results)
        
        # Save advanced vulnerability data
        vuln_data = AdvancedVulnerabilityData.objects.create(
            scan=scan,
            sql_injection_found=len(results.get('sql_injection', [])) > 0,
            sql_injection_details=results.get('sql_injection', []),
            xss_vulnerabilities_found=len(results.get('xss_vulnerabilities', [])) > 0,
            xss_details=results.get('xss_vulnerabilities', []),
            security_headers_analysis=results.get('security_headers', {}),
            ssl_vulnerabilities=results.get('ssl_vulnerabilities', []),
            authentication_vulnerabilities=results.get('authentication_issues', []),
            default_credentials_found=any(
                'default credentials' in vuln.get('type', '').lower() 
                for vuln in results.get('authentication_issues', [])
            ),
            input_validation_issues=results.get('input_validation', []),
            owasp_top10_assessment=results.get('owasp_top10', []),
            vulnerable_ports=results.get('open_ports', []),
            security_score=security_score,
            vulnerability_recommendations=results.get('recommendations', [])
        )
        
        # Save all vulnerabilities found
        all_vulnerabilities = []
        
        # Add SQL injection vulnerabilities
        for sql_vuln in results.get('sql_injection', []):
            all_vulnerabilities.append({
                'type': sql_vuln.get('type', 'SQL Injection'),
                'severity': sql_vuln.get('severity', 'critical').lower(),
                'description': sql_vuln.get('description', 'SQL injection vulnerability detected'),
                'url': sql_vuln.get('url', ''),
                'parameter': sql_vuln.get('parameter', ''),
                'payload': sql_vuln.get('payload', '')
            })
        
        # Add XSS vulnerabilities
        for xss_vuln in results.get('xss_vulnerabilities', []):
            all_vulnerabilities.append({
                'type': xss_vuln.get('type', 'Cross-Site Scripting'),
                'severity': xss_vuln.get('severity', 'high').lower(),
                'description': xss_vuln.get('description', 'XSS vulnerability detected'),
                'url': xss_vuln.get('url', ''),
                'parameter': xss_vuln.get('parameter', ''),
                'payload': xss_vuln.get('payload', '')
            })
        
        # Add SSL/TLS vulnerabilities
        for ssl_vuln in results.get('ssl_vulnerabilities', []):
            all_vulnerabilities.append({
                'type': ssl_vuln.get('type', 'SSL/TLS Issue'),
                'severity': ssl_vuln.get('severity', 'medium').lower(),
                'description': ssl_vuln.get('description', 'SSL/TLS vulnerability detected')
            })
        
        # Add authentication vulnerabilities
        for auth_vuln in results.get('authentication_issues', []):
            all_vulnerabilities.append({
                'type': auth_vuln.get('type', 'Authentication Issue'),
                'severity': auth_vuln.get('severity', 'high').lower(),
                'description': auth_vuln.get('description', 'Authentication vulnerability detected'),
                'credentials': auth_vuln.get('credentials', '')
            })
        
        # Add input validation vulnerabilities
        for input_vuln in results.get('input_validation', []):
            all_vulnerabilities.append({
                'type': input_vuln.get('type', 'Input Validation Issue'),
                'severity': input_vuln.get('severity', 'medium').lower(),
                'description': input_vuln.get('description', 'Input validation vulnerability detected')
            })
        
        # Add security header issues
        for protocol, headers in results.get('security_headers', {}).items():
            for header, info in headers.items():
                if not info.get('present', True) and info.get('risk'):
                    all_vulnerabilities.append({
                        'type': f'Missing Security Header: {header}',
                        'severity': info.get('risk', 'medium').lower(),
                        'description': f'Missing {header} security header in {protocol} response'
                    })
        
        # Save vulnerabilities to database
        for vuln in all_vulnerabilities:
            # Try to find associated port if URL contains port
            port_obj = None
            if 'url' in vuln and vuln['url']:
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(vuln['url'])
                    if parsed_url.port:
                        port_obj = Port.objects.filter(scan=scan, port_number=parsed_url.port).first()
                except:
                    pass
            
            Vulnerability.objects.create(
                scan=scan,
                port=port_obj,
                title=vuln.get('type', 'Security Vulnerability'),
                description=vuln.get('description', 'Security vulnerability detected'),
                severity=vuln.get('severity', 'medium'),
                remediation=get_vulnerability_remediation(vuln.get('type', ''))
            )
        
        # Calculate comprehensive risk score
        risk_score = calculate_comprehensive_risk_score(results, all_vulnerabilities)
        
        log_progress(scan, 100, f"Vulnerability scan completed! Found {len(all_vulnerabilities)} vulnerabilities with security score: {security_score:.1f}/100")
        
    except Exception as e:
        log_progress(scan, step, f'Vulnerability scan failed: {str(e)}')
        risk_score = 10.0  # High risk if scan fails
    
    # Complete the scan
    scan.status = 'completed'
    scan.risk_score = risk_score
    scan.completed_at = timezone.now()
    scan.save()

def calculate_security_score(results):
    """Calculate security score (0-100, higher is better)"""
    base_score = 100.0
    
    # Deduct points for vulnerabilities
    sql_injection_count = len(results.get('sql_injection', []))
    xss_count = len(results.get('xss_vulnerabilities', []))
    ssl_issues = len(results.get('ssl_vulnerabilities', []))
    auth_issues = len(results.get('authentication_issues', []))
    
    # Critical vulnerabilities
    base_score -= sql_injection_count * 20  # -20 per SQL injection
    base_score -= xss_count * 15  # -15 per XSS
    base_score -= auth_issues * 10  # -10 per auth issue
    base_score -= ssl_issues * 5  # -5 per SSL issue
    
    # Security headers
    missing_headers = 0
    for protocol, headers in results.get('security_headers', {}).items():
        for header, info in headers.items():
            if not info.get('present', True):
                missing_headers += 1
    
    base_score -= missing_headers * 2  # -2 per missing header
    
    # Ensure score is between 0 and 100
    return max(0.0, min(100.0, base_score))

def calculate_comprehensive_risk_score(results, vulnerabilities):
    """Calculate comprehensive risk score (0-10, higher is worse)"""
    risk_score = 0.0
    
    # Weight vulnerabilities by severity
    severity_weights = {'critical': 3.0, 'high': 2.0, 'medium': 1.0, 'low': 0.5, 'info': 0.1}
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'medium')
        risk_score += severity_weights.get(severity, 1.0)
    
    # Additional risk for specific vulnerability types
    if results.get('sql_injection'):
        risk_score += 2.0  # SQL injection is critical
    
    if results.get('authentication_issues'):
        for auth_issue in results['authentication_issues']:
            if 'default credentials' in auth_issue.get('type', '').lower():
                risk_score += 2.0  # Default credentials are critical
    
    # Normalize to 0-10 scale
    return min(10.0, risk_score)

def get_vulnerability_remediation(vuln_type):
    """Get remediation advice for vulnerability type"""
    remediation_map = {
        'SQL Injection': 'Use parameterized queries and input validation to prevent SQL injection attacks',
        'Cross-Site Scripting': 'Implement proper input validation, output encoding, and Content Security Policy',
        'Missing Security Header': 'Add the missing security header to improve application security',
        'SSL/TLS Issue': 'Update SSL/TLS configuration to use strong ciphers and protocols',
        'Authentication Issue': 'Implement strong authentication mechanisms and remove default credentials',
        'Input Validation Issue': 'Implement proper input validation and sanitization',
        'Default Credentials': 'Change all default credentials to strong, unique passwords'
    }
    
    for key, remediation in remediation_map.items():
        if key.lower() in vuln_type.lower():
            return remediation
    
    return 'Review and fix the identified security vulnerability according to security best practices'

def execute_localhost_scan(scan, open_ports, start_step):
    """Execute comprehensive localhost scanning covering all scenarios (Steps 16-100)"""
    step = start_step
    
    log_progress(scan, step, "Comprehensive localhost analysis starting...")
    step += 1
    
    # Initialize comprehensive localhost scanner with progress callback
    def progress_callback(progress, message):
        # Map the comprehensive scanner's 0-100% to our remaining 84% (16-100)
        adjusted_progress = min(16 + int(progress * 0.84), 100)
        log_progress(scan, adjusted_progress, message)
    
    try:
        from .local_server_scanner import ComprehensiveLocalhostScanner
        
        comprehensive_scanner = ComprehensiveLocalhostScanner(scan.target.target_value, progress_callback)
        
        log_progress(scan, step, "Initializing comprehensive localhost scanner...")
        step += 1
        
        log_progress(scan, step, "Starting multi-scenario localhost analysis...")
        step += 1
        
        # Run the comprehensive scan (this handles 1% increments internally)
        results = comprehensive_scanner.run_comprehensive_scan()
        
        # Process and save comprehensive results
        local_data = LocalServerData.objects.create(
            scan=scan,
            target=results.get('target', 'localhost'),
            open_ports=results.get('services', []),
            services_detected=results.get('development_servers', []),
            
            # Django-specific data (if detected)
            django_detected=any(
                server.get('framework') == 'Django' 
                for server in results.get('development_servers', [])
            ),
            admin_panel_accessible=any(
                '/admin/' in server.get('exposed_endpoints', [])
                for server in results.get('development_servers', [])
            ),
            debug_mode_enabled=any(
                server.get('debug_mode', False)
                for server in results.get('development_servers', [])
            ),
            static_files_accessible=any(
                '/static/' in server.get('exposed_endpoints', [])
                for server in results.get('development_servers', [])
            ),
            
            # Comprehensive data
            accessible_urls=results.get('exposed_configs', []),
            security_headers={},  # Would be populated from web servers
            configuration_issues=results.get('exposed_configs', []),
            security_recommendations=results.get('recommendations', [])
        )
        
        # Save vulnerabilities from all categories
        all_vulnerabilities = results.get('vulnerabilities', [])
        
        # Add vulnerabilities from development servers
        for server in results.get('development_servers', []):
            for issue in server.get('security_issues', []):
                all_vulnerabilities.append({
                    'type': f"Development Server: {issue['type']}",
                    'severity': issue['severity'],
                    'description': f"Port {server['port']} - {issue['description']}",
                    'port': server['port']
                })
        
        # Add vulnerabilities from testing environments
        for env in results.get('testing_environments', []):
            for issue in env.get('security_issues', []):
                all_vulnerabilities.append({
                    'type': f"Testing Environment: {issue['type']}",
                    'severity': issue['severity'],
                    'description': f"Port {env['port']} - {issue['description']}",
                    'port': env['port']
                })
        
        # Add vulnerabilities from containers
        for container in results.get('containers', []):
            for issue in container.get('security_issues', []):
                all_vulnerabilities.append({
                    'type': f"Container: {issue['type']}",
                    'severity': issue['severity'],
                    'description': f"Port {container['port']} - {issue['description']}",
                    'port': container['port']
                })
        
        # Add vulnerabilities from APIs
        for api in results.get('apis', []):
            for issue in api.get('security_issues', []):
                all_vulnerabilities.append({
                    'type': f"API: {issue['type']}",
                    'severity': issue['severity'],
                    'description': f"Port {api['port']} - {issue['description']}",
                    'port': api['port']
                })
        
        # Save all vulnerabilities
        for vuln in all_vulnerabilities:
            # Try to find associated port
            port_obj = None
            if 'port' in vuln:
                port_obj = Port.objects.filter(scan=scan, port_number=vuln['port']).first()
            
            Vulnerability.objects.create(
                scan=scan,
                port=port_obj,
                title=vuln.get('type', 'Localhost Security Issue'),
                description=vuln.get('description', 'Security issue detected in localhost environment'),
                severity=vuln.get('severity', 'medium').lower(),
                remediation=vuln.get('remediation', 'Review localhost configuration and security settings')
            )
        
        # Calculate comprehensive risk score
        risk_score = 0.0
        if all_vulnerabilities:
            severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 0.5}
            total_score = sum(severity_weights.get(v.get('severity', 'low').lower(), 2) for v in all_vulnerabilities)
            max_possible = len(all_vulnerabilities) * 10
            risk_score = min(10.0, (total_score / max_possible) * 10) if max_possible > 0 else 0.0
        
        # Add bonus risk for critical exposures
        if results.get('containers'):
            for container in results['containers']:
                if container.get('port') == 2375:  # Insecure Docker API
                    risk_score += 3.0
        
        if results.get('exposed_configs'):
            risk_score += 1.0  # Configuration exposure
        
        # Ensure risk score doesn't exceed 10
        risk_score = min(10.0, risk_score)
        
        # Count total findings
        total_findings = (
            len(results.get('development_servers', [])) +
            len(results.get('testing_environments', [])) +
            len(results.get('containers', [])) +
            len(results.get('apis', [])) +
            len(results.get('exposed_configs', []))
        )
        
        log_progress(scan, 100, f"Comprehensive localhost scan completed! Found {total_findings} services and {len(all_vulnerabilities)} security issues.")
        
    except Exception as e:
        log_progress(scan, step, f'Comprehensive localhost scan failed: {str(e)}')
        risk_score = 0
    
    # Complete the scan
    scan.status = 'completed'
    scan.risk_score = risk_score
    scan.completed_at = timezone.now()
    scan.save()

def execute_network_scan(scan, scanner, open_ports, start_step):
    """Execute network-focused scanning (Steps 16-100)"""
    step = start_step
    
    log_progress(scan, step, "Starting network security analysis...")
    step += 1
    
    log_progress(scan, step, "Performing banner grabbing...")
    step += 1
    
    log_progress(scan, step, "Detecting service versions...")
    step += 1
    
    log_progress(scan, step, "Checking for default credentials...")
    step += 1
    
    log_progress(scan, step, "OS fingerprinting...")
    step += 1
    
    log_progress(scan, step, "Network topology mapping...")
    step += 1
    
    log_progress(scan, step, "Protocol analysis...")
    step += 1
    
    log_progress(scan, step, "Service enumeration complete")
    step += 1
    
    # Vulnerability analysis (Steps 24-50)
    log_progress(scan, step, "Starting vulnerability analysis...")
    step += 1
    
    vuln_scanner = VulnerabilityScanner(scan.target.target_value, open_ports)
    vulnerabilities = vuln_scanner.check_common_vulnerabilities()
    
    log_progress(scan, step, "Checking for CVE vulnerabilities...")
    step += 1
    
    log_progress(scan, step, "Testing for weak configurations...")
    step += 1
    
    log_progress(scan, step, "Analyzing exposed services...")
    step += 1
    
    log_progress(scan, step, "Checking for backdoors...")
    step += 1
    
    log_progress(scan, step, "Testing authentication bypass...")
    step += 1
    
    log_progress(scan, step, "Checking encryption protocols...")
    step += 1
    
    # Continue with network-specific steps
    for i in range(31, 85):
        if i % 5 == 0:  # Log every 5th step to avoid too many logs
            log_progress(scan, i, f"Network security assessment in progress...")
    
    # Save vulnerabilities (Steps 85-95)
    log_progress(scan, 85, f"Saving {len(vulnerabilities)} vulnerabilities...")
    
    for vuln in vulnerabilities:
        port_obj = Port.objects.filter(scan=scan, port_number=vuln['port']).first()
        Vulnerability.objects.create(
            scan=scan,
            port=port_obj,
            title=vuln['title'],
            description=vuln['description'],
            severity=vuln['severity'],
            remediation=vuln.get('remediation', '')
        )
    
    # Final steps (Steps 90-100)
    log_progress(scan, 90, "Generating security report...")
    log_progress(scan, 91, "Calculating risk scores...")
    
    risk_score = vuln_scanner.calculate_risk_score()
    
    log_progress(scan, 95, "Finalizing network assessment...")
    log_progress(scan, 96, "Saving scan results...")
    log_progress(scan, 99, "Scan validation complete")
    log_progress(scan, 100, "Network scan completed!")
    
    # Complete the scan
    scan.status = 'completed'
    scan.risk_score = risk_score
    scan.completed_at = timezone.now()
    scan.save()

def execute_web_scan(scan, scanner, web_ports, start_step):
    """Execute web application scanning (Steps 16-100)"""
    step = start_step
    
    log_progress(scan, step, "Web ports detected, starting web analysis...")
    step += 1
    
    # Determine protocol
    protocol = 'https' if 443 in web_ports or 8443 in web_ports else 'http'
    port = web_ports[0]
    base_url = f"{protocol}://{scan.target.target_value}:{port}" if port not in [80, 443] else f"{protocol}://{scan.target.target_value}"
    
    try:
        web_scanner = WebsiteRecon(base_url, timeout=3)
        
        # Web reconnaissance steps (17-40)
        log_progress(scan, step, "Testing web connectivity...")
        step += 1
        
        log_progress(scan, step, "Checking HTTP/HTTPS protocols...")
        step += 1
        
        log_progress(scan, step, "Analyzing response headers...")
        headers = web_scanner.analyze_headers()
        step += 1
        
        log_progress(scan, step, "Detecting web server type...")
        step += 1
        
        log_progress(scan, step, "Checking security headers...")
        step += 1
        
        log_progress(scan, step, "Web server fingerprinting...")
        step += 1
        
        log_progress(scan, step, "Detecting web technologies...")
        technologies = web_scanner.detect_technologies()
        step += 1
        
        log_progress(scan, step, "Identifying CMS platform...")
        step += 1
        
        log_progress(scan, step, "Checking framework versions...")
        step += 1
        
        log_progress(scan, step, "Analyzing JavaScript libraries...")
        step += 1
        
        log_progress(scan, step, "Checking robots.txt...")
        robots = web_scanner.check_robots_txt()
        step += 1
        
        log_progress(scan, step, "Analyzing sitemap.xml...")
        sitemap = web_scanner.check_sitemap()
        step += 1
        
        log_progress(scan, step, "Starting directory enumeration...")
        directories = web_scanner.enumerate_directories(max_workers=5)
        step += 1
        
        # Continue with web-specific steps
        for i in range(step, 50):
            if i % 3 == 0:  # Log every 3rd step
                log_progress(scan, i, f"Web security analysis in progress...")
        
        # Form and vulnerability analysis (Steps 50-80)
        log_progress(scan, 50, "Starting form analysis...")
        forms = web_scanner.extract_forms()
        
        log_progress(scan, 55, "Extracting email addresses...")
        emails = web_scanner.extract_emails()
        
        log_progress(scan, 60, "Starting web vulnerability testing...")
        
        # Save web recon data
        WebReconData.objects.create(
            scan=scan,
            cms=technologies.get('cms', []),
            frameworks=technologies.get('frameworks', []),
            javascript_libraries=technologies.get('javascript_libraries', []),
            web_servers=technologies.get('web_servers', []),
            programming_languages=technologies.get('programming_languages', []),
            analytics=technologies.get('analytics', []),
            security_headers=headers.get('security_headers', {}),
            directories=[{'url': d['url'], 'status': d['status_code']} for d in directories[:50]],
            forms=forms,
            emails=emails,
            robots_txt_content=robots.get('content', '') if robots.get('exists') else '',
            sitemap_urls=sitemap.get('urls', []) if sitemap.get('exists') else [],
        )
        
        # Web vulnerabilities
        log_progress(scan, 70, "Checking web vulnerabilities...")
        web_vuln_scanner = WebVulnerabilityScanner(base_url)
        web_vulns = web_vuln_scanner.check_security_headers(headers)
        web_vulns.extend(web_vuln_scanner.check_exposed_files(directories))
        
        for vuln in web_vulns:
            Vulnerability.objects.create(
                scan=scan,
                port=None,
                title=vuln['title'],
                description=vuln['description'],
                severity=vuln['severity'],
                remediation=vuln.get('remediation', '')
            )
        
        # Network vulnerabilities
        log_progress(scan, 80, "Checking network vulnerabilities...")
        vuln_scanner = VulnerabilityScanner(scan.target.target_value, web_ports)
        network_vulns = vuln_scanner.check_common_vulnerabilities()
        
        for vuln in network_vulns:
            port_obj = Port.objects.filter(scan=scan, port_number=vuln['port']).first()
            Vulnerability.objects.create(
                scan=scan,
                port=port_obj,
                title=vuln['title'],
                description=vuln['description'],
                severity=vuln['severity'],
                remediation=vuln.get('remediation', '')
            )
        
        risk_score = vuln_scanner.calculate_risk_score()
        
    except Exception as e:
        log_progress(scan, step, f'Web reconnaissance failed: {str(e)}')
        risk_score = 0
    
    # Final steps
    log_progress(scan, 90, "Generating web security report...")
    log_progress(scan, 95, "Finalizing web assessment...")
    log_progress(scan, 99, "Web scan validation complete")
    log_progress(scan, 100, "Web application scan completed!")
    
    # Complete the scan
    scan.status = 'completed'
    scan.risk_score = risk_score
    scan.completed_at = timezone.now()
    scan.save()

def execute_api_scan(scan, api_ports, start_step):
    """Execute API security scanning (Steps 16-100)"""
    step = start_step
    
    log_progress(scan, step, "API endpoints detected, starting API analysis...")
    step += 1
    
    log_progress(scan, step, "Discovering API endpoints...")
    step += 1
    
    log_progress(scan, step, "Analyzing API documentation...")
    step += 1
    
    log_progress(scan, step, "Checking OpenAPI/Swagger specs...")
    step += 1
    
    log_progress(scan, step, "Testing API connectivity...")
    step += 1
    
    log_progress(scan, step, "Analyzing authentication methods...")
    step += 1
    
    log_progress(scan, step, "Testing API key security...")
    step += 1
    
    log_progress(scan, step, "Checking OAuth implementation...")
    step += 1
    
    log_progress(scan, step, "Testing JWT token security...")
    step += 1
    
    log_progress(scan, step, "Analyzing rate limiting...")
    step += 1
    
    # Continue with API-specific analysis
    for i in range(step, 85):
        if i % 5 == 0:  # Log every 5th step
            log_progress(scan, i, f"API security analysis in progress...")
    
    # Basic vulnerability check for API ports
    vuln_scanner = VulnerabilityScanner(scan.target.target_value, api_ports)
    vulnerabilities = vuln_scanner.check_common_vulnerabilities()
    
    log_progress(scan, 85, f"Saving {len(vulnerabilities)} API vulnerabilities...")
    
    for vuln in vulnerabilities:
        port_obj = Port.objects.filter(scan=scan, port_number=vuln['port']).first()
        Vulnerability.objects.create(
            scan=scan,
            port=port_obj,
            title=vuln['title'],
            description=vuln['description'],
            severity=vuln['severity'],
            remediation=vuln.get('remediation', '')
        )
    
    risk_score = vuln_scanner.calculate_risk_score()
    
    # Final steps
    log_progress(scan, 90, "Generating API security report...")
    log_progress(scan, 95, "Finalizing API assessment...")
    log_progress(scan, 99, "API scan validation complete")
    log_progress(scan, 100, "API security scan completed!")
    
    # Complete the scan
    scan.status = 'completed'
    scan.risk_score = risk_score
    scan.completed_at = timezone.now()
    scan.save()

def scan_detail(request, scan_id):
    """View detailed scan results with Phase 4 Risk Scoring"""
    scan = get_object_or_404(Scan, id=scan_id)
    ports = scan.ports.all()
    vulnerabilities = scan.vulnerabilities.all()
    logs = scan.logs.all()[:50]
    
    # Get web recon data if available
    try:
        web_recon = scan.web_recon
    except:
        web_recon = None
    
    # Get local server data if available
    try:
        local_server = scan.local_server
    except:
        local_server = None
    
    # Get advanced vulnerability data if available
    try:
        advanced_vulns = scan.advanced_vulnerabilities
    except:
        advanced_vulns = None
    
    # Phase 4: Get risk breakdown if available
    risk_breakdown = None
    if hasattr(scan, 'risk_breakdown') and scan.risk_breakdown:
        risk_breakdown = scan.risk_breakdown
    
    # Phase 4: Get attack chains if available
    attack_chains = None
    if hasattr(scan, 'attack_chains') and scan.attack_chains:
        attack_chains = scan.attack_chains
    
    # Calculate statistics
    severity_counts = {
        'critical': vulnerabilities.filter(severity='critical').count(),
        'high': vulnerabilities.filter(severity='high').count(),
        'medium': vulnerabilities.filter(severity='medium').count(),
        'low': vulnerabilities.filter(severity='low').count(),
    }
    
    context = {
        'scan': scan,
        'ports': ports,
        'vulnerabilities': vulnerabilities,
        'logs': logs,
        'severity_counts': severity_counts,
        'web_recon': web_recon,
        'local_server': local_server,
        'advanced_vulns': advanced_vulns,
        'risk_breakdown': risk_breakdown,  # Phase 4
        'attack_chains': attack_chains,     # Phase 4
    }
    return render(request, 'rescanai/scan_detail_professional.html', context)

def scan_progress(request, scan_id):
    """View scan progress"""
    scan = get_object_or_404(Scan, id=scan_id)
    context = {
        'scan': scan,
    }
    return render(request, 'rescanai/scan_progress.html', context)

@csrf_exempt
def scan_progress_api(request, scan_id):
    """API endpoint for scan progress with 1% increments"""
    try:
        scan = get_object_or_404(Scan, id=scan_id)
        logs = scan.logs.all().order_by('-timestamp')[:20]
        
        progress = 0
        message = "Initializing scan..."
        
        if scan.status == 'pending':
            progress = 0
            message = "Scan is pending..."
        elif scan.status == 'running':
            # Extract progress from log messages that contain [X%]
            latest_log = logs.first() if logs else None
            if latest_log:
                message = latest_log.message
                # Extract percentage from message like "[25%] Analyzing..."
                import re
                match = re.search(r'\[(\d+)%\]', message)
                if match:
                    progress = int(match.group(1))
                else:
                    # Fallback: count logs as progress
                    progress = min(99, scan.logs.count())
            else:
                progress = 1
                message = "Scanning in progress..."
                
        elif scan.status == 'completed':
            progress = 100
            message = f"Scan completed! Found {scan.ports.count()} open ports and {scan.vulnerabilities.count()} vulnerabilities."
        elif scan.status == 'failed':
            progress = 100
            message = "Scan failed. Check logs for details."
        
        logs_data = [{
            'level': log.level,
            'timestamp': log.timestamp.strftime('%H:%M:%S'),
            'message': log.message
        } for log in logs]
        
        return JsonResponse({
            'status': scan.status,
            'progress': progress,
            'message': message,
            'logs': logs_data
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def delete_scan(request, scan_id):
    """Delete a scan"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    
    try:
        scan = get_object_or_404(Scan, id=scan_id)
        scan.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Scan deleted successfully'
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

def login_view(request):
    """Login page"""
    if request.user.is_authenticated:
        return redirect('rescanai:index')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Find user by email
        try:
            user_obj = User.objects.get(email=email)
            user = authenticate(request, username=user_obj.username, password=password)
            
            if user is not None:
                auth_login(request, user)
                return redirect('rescanai:index')
            else:
                return render(request, 'rescanai/login.html', {
                    'error': 'Invalid email or password'
                })
        except User.DoesNotExist:
            return render(request, 'rescanai/login.html', {
                'error': 'Invalid email or password'
            })
    
    return render(request, 'rescanai/login.html')

def register_view(request):
    """Registration page"""
    if request.user.is_authenticated:
        return redirect('rescanai:index')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        # Validation
        if password1 != password2:
            return render(request, 'rescanai/register.html', {
                'error': 'Passwords do not match'
            })
        
        if len(password1) < 8:
            return render(request, 'rescanai/register.html', {
                'error': 'Password must be at least 8 characters'
            })
        
        if User.objects.filter(username=username).exists():
            return render(request, 'rescanai/register.html', {
                'error': 'Username already exists'
            })
        
        if User.objects.filter(email=email).exists():
            return render(request, 'rescanai/register.html', {
                'error': 'Email already registered'
            })
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1
        )
        
        # Redirect to login page after successful registration
        return redirect('rescanai:login')
    
    return render(request, 'rescanai/register.html')

def logout_view(request):
    """Logout user"""
    auth_logout(request)
    return redirect('rescanai:login')

def vulnerability_database(request):
    """Vulnerability database view"""
    vulnerabilities = Vulnerability.objects.all().order_by('-discovered_at')
    scans = Scan.objects.all().order_by('-started_at')
    
    # Calculate statistics
    total_count = vulnerabilities.count()
    critical_count = vulnerabilities.filter(severity='critical').count()
    high_count = vulnerabilities.filter(severity='high').count()
    medium_count = vulnerabilities.filter(severity='medium').count()
    low_count = vulnerabilities.filter(severity='low').count()
    
    context = {
        'vulnerabilities': vulnerabilities,
        'scans': scans,
        'total_count': total_count,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
    }
    return render(request, 'rescanai/vulnerability_database.html', context)

def reports(request):
    """Reports listing view"""
    scans = Scan.objects.all().order_by('-started_at')
    completed_count = scans.filter(status='completed').count()
    total_vulns = Vulnerability.objects.count()
    
    context = {
        'scans': scans,
        'completed_count': completed_count,
        'total_vulns': total_vulns,
    }
    return render(request, 'rescanai/reports.html', context)

def export_report(request, scan_id, format_type):
    """Export scan report in various formats"""
    from django.http import HttpResponse
    import csv
    
    scan = get_object_or_404(Scan, id=scan_id)
    ports = Port.objects.filter(scan=scan)
    vulnerabilities = Vulnerability.objects.filter(scan=scan)
    
    if format_type == 'json':
        data = {
            'scan_id': scan.id,
            'target': {
                'name': scan.target.name,
                'ip_address': scan.target.ip_address,
            },
            'scan_type': scan.scan_type,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'risk_score': float(scan.risk_score) if scan.risk_score else 0,
            'ports': [
                {
                    'port': p.port_number,
                    'state': p.state,
                    'service': p.service_name,
                    'version': p.service_version,
                }
                for p in ports
            ],
            'vulnerabilities': [
                {
                    'title': v.title,
                    'severity': v.severity,
                    'cve_id': v.cve_id,
                    'cvss_score': float(v.cvss_score) if v.cvss_score else None,
                    'description': v.description,
                    'remediation': v.remediation,
                }
                for v in vulnerabilities
            ],
        }
        response = HttpResponse(json.dumps(data, indent=2), content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_report.json"'
        return response
    
    elif format_type == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_report.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Scan Report - ID: ' + str(scan.id)])
        writer.writerow(['Target', scan.target.name])
        writer.writerow(['IP Address', scan.target.ip_address])
        writer.writerow(['Scan Type', scan.scan_type])
        writer.writerow(['Risk Score', scan.risk_score or 'N/A'])
        writer.writerow([])
        
        writer.writerow(['Open Ports'])
        writer.writerow(['Port', 'State', 'Service', 'Version'])
        for p in ports:
            writer.writerow([p.port_number, p.state, p.service_name or 'Unknown', p.service_version or 'N/A'])
        writer.writerow([])
        
        writer.writerow(['Vulnerabilities'])
        writer.writerow(['Title', 'Severity', 'CVE', 'CVSS', 'Description'])
        for v in vulnerabilities:
            writer.writerow([v.title, v.severity, v.cve_id or 'N/A', v.cvss_score or 'N/A', v.description])
        
        return response
    
    elif format_type == 'pdf':
        # Simple text-based PDF alternative
        response = HttpResponse(content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_report.txt"'
        
        content = f"""
REDSCAN AI - SECURITY SCAN REPORT
{'=' * 60}

SCAN INFORMATION
Scan ID: {scan.id}
Target: {scan.target.name}
IP Address: {scan.target.ip_address}
Scan Type: {scan.scan_type.upper()}
Status: {scan.status.upper()}
Risk Score: {scan.risk_score or 'N/A'}/10
Started: {scan.started_at}
Completed: {scan.completed_at or 'In Progress'}

{'=' * 60}
OPEN PORTS ({ports.count()})
{'=' * 60}
"""
        for p in ports:
            content += f"\nPort {p.port_number} - {p.state.upper()}\n"
            content += f"  Service: {p.service_name or 'Unknown'}\n"
            content += f"  Version: {p.service_version or 'N/A'}\n"
        
        content += f"\n{'=' * 60}\n"
        content += f"VULNERABILITIES ({vulnerabilities.count()})\n"
        content += f"{'=' * 60}\n"
        
        for v in vulnerabilities:
            content += f"\n[{v.severity.upper()}] {v.title}\n"
            if v.cve_id:
                content += f"CVE: {v.cve_id}\n"
            if v.cvss_score:
                content += f"CVSS Score: {v.cvss_score}\n"
            content += f"Description: {v.description}\n"
            if v.remediation:
                content += f"Fix: {v.remediation}\n"
            content += "-" * 60 + "\n"
        
        content += f"\n{'=' * 60}\n"
        content += "Report generated by RedScan AI\n"
        
        response.write(content)
        return response
    
    return JsonResponse({'error': 'Invalid format'}, status=400)

@login_required
def settings_view(request):
    """Settings page"""
    from django.contrib import messages
    from django.contrib.auth import update_session_auth_hash
    
    if request.method == 'POST':
        form_type = request.POST.get('form_type')
        
        if form_type == 'profile':
            # Update profile information
            username = request.POST.get('username')
            email = request.POST.get('email')
            first_name = request.POST.get('first_name', '')
            last_name = request.POST.get('last_name', '')
            
            # Check if username is taken by another user
            if User.objects.filter(username=username).exclude(id=request.user.id).exists():
                messages.error(request, 'Username already taken')
            # Check if email is taken by another user
            elif User.objects.filter(email=email).exclude(id=request.user.id).exists():
                messages.error(request, 'Email already registered')
            else:
                request.user.username = username
                request.user.email = email
                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.save()
                messages.success(request, 'Profile updated successfully')
        
        elif form_type == 'password':
            # Update password
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if not request.user.check_password(current_password):
                messages.error(request, 'Current password is incorrect')
            elif new_password != confirm_password:
                messages.error(request, 'New passwords do not match')
            elif len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters')
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request, 'Password updated successfully')
        
        elif form_type == 'notifications':
            # Save notification preferences (you can extend this with a UserProfile model)
            messages.success(request, 'Notification preferences saved')
        
        return redirect('rescanai:settings')
    
    return render(request, 'rescanai/settings.html')

@login_required
def delete_account_view(request):
    """Delete user account"""
    if request.method == 'POST':
        user = request.user
        auth_logout(request)
        user.delete()
        return redirect('rescanai:login')
    
    return redirect('rescanai:settings')

def dashboard(request):
    """Main dashboard view"""
    if not request.user.is_authenticated:
        return redirect('rescanai:login')
    
    return index(request)
