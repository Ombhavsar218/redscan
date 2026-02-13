from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Target(models.Model):
    """Stores information about scan targets (IPs, domains, networks)"""
    TARGET_TYPES = [
        ('ip', 'Single IP'),
        ('domain', 'Domain'),
        ('network', 'Network Range'),
    ]
    
    name = models.CharField(max_length=255)
    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    target_value = models.CharField(max_length=255)  # IP, domain, or CIDR
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} ({self.target_value})"

class Scan(models.Model):
    """Represents a scanning session"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=50)  # 'recon', 'vuln_scan', 'full'
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    risk_score = models.FloatField(default=0.0)  # 0-100 risk score
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"Scan {self.id} - {self.target.name} ({self.status})"

class Port(models.Model):
    """Discovered open ports"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=20, default='open')
    
    class Meta:
        unique_together = ['scan', 'port_number', 'protocol']
    
    def __str__(self):
        return f"{self.port_number}/{self.protocol} - {self.service}"

class Vulnerability(models.Model):
    """Discovered vulnerabilities"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    port = models.ForeignKey(Port, on_delete=models.SET_NULL, null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True)  # 0-10 risk score
    cve_id = models.CharField(max_length=50, blank=True)
    remediation = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.title} ({self.severity})"

class ScanLog(models.Model):
    """Logs for debugging and audit trail"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=20)  # INFO, WARNING, ERROR
    message = models.TextField()
    
    class Meta:
        ordering = ['-timestamp']


class WebReconData(models.Model):
    """Stores web reconnaissance results"""
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='web_recon')
    
    # Technology Detection
    cms = models.JSONField(default=list, blank=True)  # ['WordPress', 'Joomla']
    frameworks = models.JSONField(default=list, blank=True)
    javascript_libraries = models.JSONField(default=list, blank=True)
    web_servers = models.JSONField(default=list, blank=True)
    programming_languages = models.JSONField(default=list, blank=True)
    analytics = models.JSONField(default=list, blank=True)
    
    # Security Headers
    security_headers = models.JSONField(default=dict, blank=True)
    
    # Discovered URLs and Directories
    discovered_urls = models.JSONField(default=list, blank=True)
    directories = models.JSONField(default=list, blank=True)
    
    # Forms and Emails
    forms = models.JSONField(default=list, blank=True)
    emails = models.JSONField(default=list, blank=True)
    
    # Standard Files
    robots_txt_content = models.TextField(blank=True)
    sitemap_urls = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Web Recon for Scan {self.scan.id}"

class LocalServerData(models.Model):
    """Stores localhost/local server scan results with Django-specific analysis"""
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='local_server')
    
    # Target Information
    target = models.CharField(max_length=200, default='localhost')
    
    # Port and Service Discovery
    open_ports = models.JSONField(default=list, blank=True)  # [{'port': 8000, 'service': 'Django'}]
    services_detected = models.JSONField(default=list, blank=True)
    
    # Django-Specific Information
    django_detected = models.BooleanField(default=False)
    django_version = models.CharField(max_length=50, blank=True)
    admin_panel_accessible = models.BooleanField(default=False)
    admin_url = models.CharField(max_length=200, blank=True)
    debug_mode_enabled = models.BooleanField(default=False)
    static_files_accessible = models.BooleanField(default=False)
    accessible_urls = models.JSONField(default=list, blank=True)
    
    # Security Analysis
    security_headers = models.JSONField(default=dict, blank=True)
    missing_security_headers = models.JSONField(default=list, blank=True)
    configuration_issues = models.JSONField(default=list, blank=True)
    
    # Recommendations
    security_recommendations = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Local Server Scan for {self.target} (Scan {self.scan.id})"

class AdvancedVulnerabilityData(models.Model):
    """Stores advanced vulnerability scan results"""
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='advanced_vulnerabilities')
    
    # SQL Injection Results
    sql_injection_found = models.BooleanField(default=False)
    sql_injection_details = models.JSONField(default=list, blank=True)
    
    # XSS Results
    xss_vulnerabilities_found = models.BooleanField(default=False)
    xss_details = models.JSONField(default=list, blank=True)
    
    # Security Headers Analysis
    security_headers_analysis = models.JSONField(default=dict, blank=True)
    missing_security_headers = models.JSONField(default=list, blank=True)
    
    # SSL/TLS Analysis
    ssl_vulnerabilities = models.JSONField(default=list, blank=True)
    ssl_configuration_issues = models.JSONField(default=list, blank=True)
    
    # Authentication Issues
    authentication_vulnerabilities = models.JSONField(default=list, blank=True)
    default_credentials_found = models.BooleanField(default=False)
    
    # Input Validation Issues
    input_validation_issues = models.JSONField(default=list, blank=True)
    
    # OWASP Top 10 Assessment
    owasp_top10_assessment = models.JSONField(default=list, blank=True)
    
    # Open Ports with Vulnerability Assessment
    vulnerable_ports = models.JSONField(default=list, blank=True)
    
    # Overall Security Score (0-100)
    security_score = models.FloatField(default=0.0)
    
    # Recommendations
    vulnerability_recommendations = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Advanced Vulnerability Scan for {self.scan.target.name} (Scan {self.scan.id})"
