#!/usr/bin/env python3
"""
Demo script showing the Quick Scan functionality
Demonstrates the four core Quick Scan options:
- Common web ports
- Basic SQLi check  
- Basic XSS check
- Header analysis
"""

import sys
import os
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from rescanai.scan_controller import ScanController


def demo_quick_scan_options():
    """Demonstrate each Quick Scan option individually"""
    
    print("🔹 QUICK SCAN OPTIONS DEMO")
    print("=" * 60)
    print("Demonstrating the four core Quick Scan options:")
    print("☑ Common web ports")
    print("☑ Basic SQLi check") 
    print("☑ Basic XSS check")
    print("☑ Header analysis")
    print("=" * 60)
    
    target = "httpbin.org"  # Safe test target
    
    def progress_callback(progress, message):
        print(f"[{progress:3d}%] {message}")
    
    # Test each option individually
    options_tests = [
        {
            'name': '🔓 Common Web Ports Only',
            'options': {
                'quick_common_ports': True,
                'quick_basic_sqli': False,
                'quick_basic_xss': False,
                'quick_header_analysis': False
            }
        },
        {
            'name': '🔒 Security Headers Only',
            'options': {
                'quick_common_ports': True,  # Need ports for web analysis
                'quick_basic_sqli': False,
                'quick_basic_xss': False,
                'quick_header_analysis': True
            }
        },
        {
            'name': '💉 SQL Injection Testing Only',
            'options': {
                'quick_common_ports': True,  # Need ports for web analysis
                'quick_basic_sqli': True,
                'quick_basic_xss': False,
                'quick_header_analysis': False
            }
        },
        {
            'name': '🚨 XSS Testing Only',
            'options': {
                'quick_common_ports': True,  # Need ports for web analysis
                'quick_basic_sqli': False,
                'quick_basic_xss': True,
                'quick_header_analysis': False
            }
        },
        {
            'name': '🎯 All Quick Scan Options',
            'options': {
                'quick_common_ports': True,
                'quick_basic_sqli': True,
                'quick_basic_xss': True,
                'quick_header_analysis': True
            }
        }
    ]
    
    for i, test in enumerate(options_tests, 1):
        print(f"\n{'='*20} TEST {i}/5 {'='*20}")
        print(f"🧪 {test['name']}")
        print("-" * 50)
        
        try:
            controller = ScanController(
                target=target,
                scan_type='quick',
                progress_callback=progress_callback
            )
            
            results = controller.execute_scan(test['options'])
            
            # Show results summary
            print(f"\n📊 Results Summary:")
            print(f"   🔍 Open Ports: {len(results.get('ports', []))}")
            print(f"   ⚠️  Vulnerabilities: {len(results.get('vulnerabilities', []))}")
            print(f"   📈 Risk Score: {results.get('risk_score', 0):.1f}/10")
            
            # Show what was tested
            web_data = results.get('web_data', {})
            tested_components = []
            
            if 'headers' in web_data:
                tested_components.append("Security Headers")
            if 'sqli' in web_data:
                tested_components.append("SQL Injection")
            if 'xss' in web_data:
                tested_components.append("XSS Testing")
            
            if tested_components:
                print(f"   🧪 Components Tested: {', '.join(tested_components)}")
            
        except Exception as e:
            print(f"❌ Test failed: {str(e)}")
    
    print(f"\n{'='*60}")
    print("✅ Quick Scan Options Demo Complete!")
    print("\nThe modular architecture allows users to:")
    print("• Choose exactly which security tests to run")
    print("• Get fast results with targeted scanning")
    print("• Customize their security assessment approach")
    print("• Scale from quick checks to comprehensive audits")


def show_quick_scan_benefits():
    """Show the benefits of the Quick Scan approach"""
    
    print("\n🎯 QUICK SCAN BENEFITS")
    print("=" * 40)
    print("✅ Fast Results: Complete scan in under 2 minutes")
    print("✅ Essential Coverage: Tests the most critical vulnerabilities")
    print("✅ User-Friendly: Simple checkbox interface")
    print("✅ Actionable: Clear recommendations for each finding")
    print("✅ Scalable: Can be extended to full comprehensive scans")
    
    print("\n🔹 Quick Scan vs Full Scan Comparison:")
    print("-" * 40)
    print("Quick Scan:")
    print("  • 7 common web ports (80, 443, 8080, etc.)")
    print("  • Basic SQL injection patterns")
    print("  • Basic XSS payloads")
    print("  • Essential security headers")
    print("  • ~1-2 minutes execution time")
    
    print("\nFull Scan:")
    print("  • All 65,535 ports")
    print("  • Advanced SQL injection techniques")
    print("  • Comprehensive XSS testing")
    print("  • Complete security header analysis")
    print("  • Service detection and enumeration")
    print("  • ~15-30 minutes execution time")


if __name__ == "__main__":
    demo_quick_scan_options()
    show_quick_scan_benefits()