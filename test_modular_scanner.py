#!/usr/bin/env python3
"""
Test script for the modular scanner implementation
Tests the Quick Scan functionality with the four core options
"""

import sys
import os
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from rescanai.scan_controller import ScanController


def test_quick_scan():
    """Test the Quick Scan functionality"""
    print("🔹 Testing Quick Scan Implementation")
    print("=" * 50)
    
    # Test target (using a safe test target)
    target = "scanme.nmap.org"
    
    # Quick scan options (the four core options)
    scan_options = {
        'quick_common_ports': True,
        'quick_basic_sqli': True,
        'quick_basic_xss': True,
        'quick_header_analysis': True
    }
    
    def progress_callback(progress, message):
        print(f"[{progress:3d}%] {message}")
    
    try:
        # Initialize scan controller
        print(f"🎯 Target: {target}")
        print(f"📋 Scan Type: Quick Scan")
        print(f"⚙️  Options: {list(scan_options.keys())}")
        print()
        
        controller = ScanController(
            target=target,
            scan_type='quick',
            progress_callback=progress_callback
        )
        
        # Execute the scan
        print("🚀 Starting Quick Scan...")
        results = controller.execute_scan(scan_options)
        
        # Display results
        print("\n" + "=" * 50)
        print("📊 SCAN RESULTS")
        print("=" * 50)
        
        print(f"🎯 Target: {results.get('target')}")
        print(f"📋 Scan Type: {results.get('scan_type')}")
        print(f"🔍 Open Ports: {len(results.get('ports', []))}")
        print(f"⚠️  Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        print(f"📈 Risk Score: {results.get('risk_score', 0):.1f}/10")
        
        # Show discovered ports
        if results.get('ports'):
            print(f"\n🔓 Open Ports:")
            for port in results['ports']:
                service = results.get('services', {}).get(port, 'unknown')
                print(f"   • Port {port} - {service}")
        
        # Show vulnerabilities
        if results.get('vulnerabilities'):
            print(f"\n⚠️  Vulnerabilities Found:")
            for vuln in results['vulnerabilities']:
                severity = vuln.get('severity', 'unknown').upper()
                vuln_type = vuln.get('type', 'Unknown')
                print(f"   • [{severity}] {vuln_type}")
                if vuln.get('description'):
                    print(f"     {vuln['description']}")
        
        # Show recommendations
        if results.get('recommendations'):
            print(f"\n💡 Recommendations:")
            for rec in results['recommendations']:
                print(f"   • {rec}")
        
        print("\n✅ Quick Scan test completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Quick Scan test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_scan_controller_initialization():
    """Test scan controller initialization"""
    print("\n🔧 Testing Scan Controller Initialization")
    print("-" * 40)
    
    try:
        controller = ScanController("127.0.0.1", "quick")
        print("✅ Scan Controller initialized successfully")
        
        # Test module initialization
        print(f"✅ Port Scanner: {type(controller.port_scanner).__name__}")
        print(f"✅ Web Scanner: {type(controller.web_scanner).__name__}")
        print(f"✅ API Scanner: {type(controller.api_scanner).__name__}")
        print(f"✅ Risk Analyzer: {type(controller.risk_analyzer).__name__}")
        
        return True
        
    except Exception as e:
        print(f"❌ Initialization failed: {str(e)}")
        return False


def main():
    """Main test function"""
    print("🔹 MODULAR SCANNER TEST SUITE")
    print("=" * 60)
    
    # Test 1: Initialization
    init_success = test_scan_controller_initialization()
    
    if init_success:
        # Test 2: Quick Scan (only if initialization succeeded)
        print("\n" + "=" * 60)
        scan_success = test_quick_scan()
        
        if scan_success:
            print("\n🎉 ALL TESTS PASSED!")
            print("The modular scanner implementation is working correctly.")
        else:
            print("\n⚠️  Some tests failed. Check the error messages above.")
    else:
        print("\n❌ Initialization failed. Cannot proceed with scan tests.")


if __name__ == "__main__":
    main()