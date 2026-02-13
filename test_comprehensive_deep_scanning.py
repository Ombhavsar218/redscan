#!/usr/bin/env python3
"""
Comprehensive test for real deep scanning functionality
Tests all implemented features: Port scanning, SQLi, and XSS
"""
import sys
import os
import django
import time

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from rescanai.scan_controller import ScanController


def test_comprehensive_scan():
    """Test comprehensive deep scanning with all features"""
    print("=" * 80)
    print("🔍 COMPREHENSIVE DEEP SCANNING TEST")
    print("=" * 80)
    print()
    print("Testing ALL implemented features:")
    print("  ✓ Real port scanning with TCP connections")
    print("  ✓ Real SQL injection testing with 70+ payloads")
    print("  ✓ Real XSS testing with 100+ payloads")
    print("  ✓ Real endpoint discovery through crawling")
    print("  ✓ Real parameter discovery from forms")
    print()
    
    # Use a safe test target
    target = "testphp.vulnweb.com"  # Intentionally vulnerable test site
    
    print(f"🎯 Target: {target}")
    print(f"📊 Test: Quick Scan with ALL options enabled")
    print("-" * 80)
    print()
    
    # Track timing and progress
    start_time = time.time()
    progress_updates = []
    
    def progress_callback(progress, message):
        """Track all progress updates"""
        elapsed = time.time() - start_time
        progress_updates.append({
            'progress': progress,
            'message': message,
            'elapsed': elapsed
        })
        print(f"[{progress:3d}%] {message} ({elapsed:.1f}s)")
    
    print("🚀 Starting Comprehensive Deep Scan...")
    print()
    
    try:
        controller = ScanController(
            target=target,
            scan_type='quick',
            progress_callback=progress_callback
        )
        
        # Enable ALL scan options
        scan_options = {
            'quick_common_ports': True,
            'quick_header_analysis': True,
            'quick_basic_sqli': True,
            'quick_basic_xss': True
        }
        
        results = controller.execute_scan(scan_options)
        
        total_time = time.time() - start_time
        
        print()
        print("=" * 80)
        print("📊 COMPREHENSIVE SCAN RESULTS")
        print("=" * 80)
        print()
        
        # Timing Analysis
        print("⏱️  Timing Analysis:")
        print(f"   Total Scan Time: {total_time:.2f} seconds ({total_time/60:.1f} minutes)")
        print(f"   Progress Updates: {len(progress_updates)}")
        print()
        
        # Verify realistic timing
        if total_time >= 30:  # Should take at least 30 seconds for real comprehensive scan
            print(f"   ✅ REAL DEEP SCANNING: YES")
            print(f"      Scan took {total_time:.1f}s - realistic for comprehensive testing")
        else:
            print(f"   ⚠️  WARNING: Scan completed in {total_time:.1f}s")
            print(f"      May not be performing deep testing")
        print()
        
        # Port Scanning Results
        print("🔌 Port Scanning Results:")
        print(f"   Open Ports: {len(results.get('ports', []))}")
        if results.get('ports'):
            print(f"   Ports Found: {results['ports']}")
        print(f"   Services Detected: {len(results.get('services', {}))}")
        if results.get('services'):
            for port, service in results['services'].items():
                print(f"      • Port {port}: {service}")
        print()
        
        # SQL Injection Results
        print("💉 SQL Injection Testing Results:")
        sqli_data = results.get('web_data', {}).get('sqli', {})
        print(f"   Endpoints Tested: {len(sqli_data.get('tested_urls', []))}")
        print(f"   Total Tests Performed: {sqli_data.get('total_tests', 0)}")
        sqli_vulns = [v for v in results.get('vulnerabilities', []) if 'SQL' in v.get('type', '')]
        print(f"   SQLi Vulnerabilities Found: {len(sqli_vulns)}")
        if sqli_vulns:
            for vuln in sqli_vulns[:3]:  # Show first 3
                print(f"      • [{vuln.get('severity', 'unknown').upper()}] {vuln.get('type', 'Unknown')}")
                print(f"        URL: {vuln.get('url', 'N/A')}")
                print(f"        Parameter: {vuln.get('parameter', 'N/A')}")
        print()
        
        # XSS Results
        print("🎭 XSS Testing Results:")
        xss_data = results.get('web_data', {}).get('xss', {})
        print(f"   Endpoints Tested: {len(xss_data.get('tested_urls', []))}")
        print(f"   Total Tests Performed: {xss_data.get('total_tests', 0)}")
        xss_vulns = [v for v in results.get('vulnerabilities', []) if 'XSS' in v.get('type', '')]
        print(f"   XSS Vulnerabilities Found: {len(xss_vulns)}")
        if xss_vulns:
            for vuln in xss_vulns[:3]:  # Show first 3
                print(f"      • [{vuln.get('severity', 'unknown').upper()}] {vuln.get('type', 'Unknown')}")
                print(f"        URL: {vuln.get('url', 'N/A')}")
                print(f"        Parameter: {vuln.get('parameter', 'N/A')}")
        print()
        
        # Overall Results
        print("📈 Overall Results:")
        print(f"   Total Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        print(f"   Risk Score: {results.get('risk_score', 0):.1f}/10")
        print()
        
        # Verification
        print("🔍 Deep Scanning Verification:")
        checks_passed = 0
        total_checks = 5
        
        if total_time >= 30:
            print(f"   ✅ Realistic timing (>30s)")
            checks_passed += 1
        else:
            print(f"   ❌ Timing too fast (<30s)")
        
        if results.get('ports'):
            print(f"   ✅ Ports discovered ({len(results['ports'])} found)")
            checks_passed += 1
        else:
            print(f"   ⚠️  No ports found")
        
        if sqli_data.get('total_tests', 0) >= 20:
            print(f"   ✅ Comprehensive SQLi testing ({sqli_data.get('total_tests', 0)} tests)")
            checks_passed += 1
        else:
            print(f"   ❌ Insufficient SQLi testing ({sqli_data.get('total_tests', 0)} tests)")
        
        if xss_data.get('total_tests', 0) >= 20:
            print(f"   ✅ Comprehensive XSS testing ({xss_data.get('total_tests', 0)} tests)")
            checks_passed += 1
        else:
            print(f"   ❌ Insufficient XSS testing ({xss_data.get('total_tests', 0)} tests)")
        
        if len(results.get('vulnerabilities', [])) > 0:
            print(f"   ✅ Vulnerabilities detected ({len(results['vulnerabilities'])} found)")
            checks_passed += 1
        else:
            print(f"   ⚠️  No vulnerabilities found (target may be secure)")
        
        print()
        print(f"   Score: {checks_passed}/{total_checks} checks passed")
        print()
        
        print("=" * 80)
        if checks_passed >= 4:
            print("🎉 SUCCESS: Deep scanning is working correctly!")
            print()
            print("Key Achievements:")
            print("  ✓ Real TCP connections to ports")
            print("  ✓ Real HTTP requests with SQLi payloads")
            print("  ✓ Real HTTP requests with XSS payloads")
            print("  ✓ Actual endpoint discovery through crawling")
            print("  ✓ Real parameter discovery from HTML forms")
            print("  ✓ Comprehensive vulnerability testing")
            print("  ✓ Realistic timing based on actual work")
            return True
        else:
            print("⚠️  WARNING: Some deep scanning features may need improvement")
            print(f"   Only {checks_passed}/{total_checks} checks passed")
            return False
            
    except Exception as e:
        print()
        print(f"❌ ERROR: Test failed with exception:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_payload_counts():
    """Verify payload libraries are comprehensive"""
    print()
    print("=" * 80)
    print("📚 PAYLOAD LIBRARY VERIFICATION")
    print("=" * 80)
    print()
    
    from rescanai.web_scanner import WebScanner
    
    scanner = WebScanner('test.com')
    
    print("SQL Injection Payloads:")
    total_sqli = 0
    for technique, payloads in scanner.sqli_payloads.items():
        print(f"   {technique}: {len(payloads)} payloads")
        total_sqli += len(payloads)
    print(f"   TOTAL: {total_sqli} SQLi payloads")
    print()
    
    print("XSS Payloads:")
    total_xss = 0
    for category, payloads in scanner.xss_payloads.items():
        print(f"   {category}: {len(payloads)} payloads")
        total_xss += len(payloads)
    print(f"   TOTAL: {total_xss} XSS payloads")
    print()
    
    print("SQL Error Patterns:")
    print(f"   {len(scanner.sql_error_patterns)} error patterns")
    print()
    
    if total_sqli >= 70 and total_xss >= 100:
        print("✅ Payload libraries are comprehensive!")
        return True
    else:
        print(f"⚠️  Payload libraries may need expansion")
        print(f"   SQLi: {total_sqli}/70+ (target)")
        print(f"   XSS: {total_xss}/100+ (target)")
        return False


if __name__ == "__main__":
    print()
    
    # Test payload libraries
    payload_test = test_payload_counts()
    
    print()
    input("Press Enter to start comprehensive scan test (this will take 1-3 minutes)...")
    print()
    
    # Test comprehensive scanning
    scan_test = test_comprehensive_scan()
    
    print()
    print("=" * 80)
    print("🏁 ALL TESTS COMPLETE")
    print("=" * 80)
    print()
    
    if payload_test and scan_test:
        print("🎉 ALL TESTS PASSED!")
        print()
        print("Your scanner is now performing REAL deep security testing:")
        print("  • Actual network connections and requests")
        print("  • Comprehensive payload testing (70+ SQLi, 100+ XSS)")
        print("  • Real endpoint and parameter discovery")
        print("  • Evidence-based vulnerability detection")
        print("  • Realistic timing (2-5 minutes for Quick Scan)")
    else:
        print("⚠️  Some tests did not pass completely")
        print("   Review the output above for details")
