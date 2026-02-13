"""
Test minimal template syntax to isolate the issue
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

def test_minimal_template():
    """Test a minimal template"""
    try:
        # Get a completed scan
        scan = Scan.objects.filter(status='completed').first()
        if not scan:
            print("No completed scans found")
            return
        
        print(f"Testing minimal template with scan {scan.id}")
        
        # Minimal context
        context = {
            'scan': scan,
            'ports': scan.ports.all(),
            'vulnerabilities': scan.vulnerabilities.all(),
        }
        
        # Try to render the minimal template
        html = render_to_string('rescanai/test_minimal.html', context)
        print("✅ Minimal template rendered successfully!")
        print(f"HTML length: {len(html)} characters")
        
    except Exception as e:
        print(f"❌ Minimal template error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_minimal_template()