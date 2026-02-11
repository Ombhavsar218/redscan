from django.contrib import admin
from .models import Target, Scan, Port, Vulnerability, ScanLog

@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ['name', 'target_type', 'target_value', 'created_by', 'created_at']
    list_filter = ['target_type', 'created_at']
    search_fields = ['name', 'target_value']

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'scan_type', 'status', 'started_at', 'completed_at']
    list_filter = ['status', 'scan_type', 'started_at']
    readonly_fields = ['started_at', 'completed_at']

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ['port_number', 'protocol', 'service', 'version', 'state', 'scan']
    list_filter = ['protocol', 'state']
    search_fields = ['service', 'port_number']

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'cvss_score', 'cve_id', 'scan', 'discovered_at']
    list_filter = ['severity', 'discovered_at']
    search_fields = ['title', 'cve_id', 'description']

@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ['scan', 'level', 'timestamp', 'message']
    list_filter = ['level', 'timestamp']
