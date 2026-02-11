"""
Quick setup script for RedScan AI
Run this after installing requirements
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from django.contrib.auth.models import User
from rescanai.models import Target

def setup():
    print("🔴 RedScan AI - Setup Script")
    print("=" * 50)
    
    # Create demo target
    print("\n[*] Creating demo target...")
    target, created = Target.objects.get_or_create(
        name="Scanme Demo",
        defaults={
            'target_type': 'domain',
            'target_value': 'scanme.nmap.org',
            'description': 'Official Nmap test server - safe to scan',
            'created_by': User.objects.first() or User.objects.create_user('admin')
        }
    )
    
    if created:
        print(f"[+] Created target: {target.name} ({target.target_value})")
    else:
        print(f"[!] Target already exists: {target.name}")
    
    print("\n✅ Setup complete!")
    print("\nNext steps:")
    print("1. Run: python manage.py runserver")
    print("2. Visit: http://127.0.0.1:8000/")
    print("3. Start a scan using the API or admin panel")
    print(f"\nDemo target ID: {target.id}")
    print(f"Test scan: curl -X POST http://127.0.0.1:8000/scan/start/ -H 'Content-Type: application/json' -d '{{\"target_id\": {target.id}, \"scan_type\": \"recon\"}}'")

if __name__ == '__main__':
    setup()
