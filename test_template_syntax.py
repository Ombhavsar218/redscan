"""
Test template syntax to isolate the issue
"""

import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from django.template.loader import render_to_string
from rescanai.models import Scan

def test_template():
    """Test the scan_detail template with minimal context"""
    try:
        # Get a completed scan
        scan = Scan.objects.filter(status='completed').first()
        if not scan:
            print("No completed scans found")
            return
        
        print(f"Testing with scan {scan.id}")
        
        # Minimal context
        context = {
            'scan': scan,
            'ports': scan.ports.all(),
            'vulnerabilities': scan.vulnerabilities.all(),
            'logs': scan.logs.all()[:10],
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'web_recon': None,
            'local_server': None,
            'advanced_vulns': None,
            'risk_breakdown': None,
            'attack_chains': None,
        }
        
        # Try to render the template
        html = render_to_string('rescanai/scan_detail.html', context)
        print("✅ Template rendered successfully!")
        print(f"HTML length: {len(html)} characters")
        
    except Exception as e:
        print(f"❌ Template error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_template()