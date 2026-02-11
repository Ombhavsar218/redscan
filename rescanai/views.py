from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Target, Scan, Port, Vulnerability, ScanLog
from .scanner import NetworkScanner, VulnerabilityScanner, ReconEngine
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
        
        scan_type = data.get('scan_type', 'recon')
        
        # Create scan record
        scan = Scan.objects.create(
            target=target,
            scan_type=scan_type,
            status='pending',
            created_by=request.user if request.user.is_authenticated else target.created_by
        )
        
        # Run scan in background thread
        thread = Thread(target=execute_scan, args=(scan.id,))
        thread.start()
        
        return JsonResponse({
            'success': True,
            'scan_id': scan.id,
            'message': 'Scan started'
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

def execute_scan(scan_id: int):
    """
    Execute the actual scanning process
    This runs in a background thread
    """
    scan = Scan.objects.get(id=scan_id)
    
    try:
        scan.status = 'running'
        scan.save()
        
        # Log start
        ScanLog.objects.create(
            scan=scan,
            level='INFO',
            message=f'Starting {scan.scan_type} scan on {scan.target.target_value}'
        )
        
        # Initialize scanner
        scanner = NetworkScanner(scan.target.target_value)
        
        # Determine port range based on scan type
        if scan.scan_type == 'quick':
            port_range = range(1, 1025)
        elif scan.scan_type == 'full':
            port_range = range(1, 65536)
        elif scan.scan_type == 'web':
            port_range = [80, 443, 8080, 8443, 8000, 3000, 5000]
        else:  # custom or default
            port_range = range(1, 1025)
        
        # Port scanning
        open_ports = scanner.scan_ports(port_range)
        
        # Save discovered ports
        for port_num in open_ports:
            service = scanner.results['services'].get(port_num, 'unknown')
            banner = scanner.banner_grab(port_num)
            
            Port.objects.create(
                scan=scan,
                port_number=port_num,
                service=service,
                version=banner[:255] if banner else '',
                state='open'
            )
        
        ScanLog.objects.create(
            scan=scan,
            level='INFO',
            message=f'Found {len(open_ports)} open ports'
        )
        
        # Vulnerability scanning
        vuln_scanner = VulnerabilityScanner(scan.target.target_value, open_ports)
        vulnerabilities = vuln_scanner.check_common_vulnerabilities()
        
        # Save vulnerabilities
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
        
        # Calculate risk score
        risk_score = vuln_scanner.calculate_risk_score()
        
        ScanLog.objects.create(
            scan=scan,
            level='INFO',
            message=f'Scan completed. Risk score: {risk_score:.2f}/10'
        )
        
        scan.status = 'completed'
        scan.risk_score = risk_score
        scan.completed_at = timezone.now()
        scan.save()
        
    except Exception as e:
        scan.status = 'failed'
        scan.save()
        
        ScanLog.objects.create(
            scan=scan,
            level='ERROR',
            message=f'Scan failed: {str(e)}'
        )

def scan_detail(request, scan_id):
    """View detailed scan results"""
    scan = get_object_or_404(Scan, id=scan_id)
    ports = scan.ports.all()
    vulnerabilities = scan.vulnerabilities.all()
    logs = scan.logs.all()[:50]
    
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
    }
    return render(request, 'rescanai/scan_detail.html', context)

def scan_progress(request, scan_id):
    """View scan progress"""
    scan = get_object_or_404(Scan, id=scan_id)
    context = {
        'scan': scan,
    }
    return render(request, 'rescanai/scan_progress.html', context)

@csrf_exempt
def scan_progress_api(request, scan_id):
    """API endpoint for scan progress"""
    try:
        scan = get_object_or_404(Scan, id=scan_id)
        logs = scan.logs.all().order_by('-timestamp')[:20]
        
        # Calculate progress based on status and logs
        progress = 0
        message = "Initializing scan..."
        
        if scan.status == 'pending':
            progress = 0
            message = "Scan is pending..."
        elif scan.status == 'running':
            # Estimate progress based on logs
            log_count = scan.logs.count()
            if log_count > 0:
                progress = min(90, log_count * 10)  # Cap at 90% until complete
                latest_log = logs.first()
                if latest_log:
                    message = latest_log.message
            else:
                progress = 10
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
