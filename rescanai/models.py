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
    risk_score = models.FloatField(default=0.0)  # 0-10 risk score
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
