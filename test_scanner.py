"""
Test script to demonstrate scanner functionality
Run this to test the scanning engine independently
"""
from rescanai.scanner import NetworkScanner, VulnerabilityScanner, ReconEngine

def test_basic_scan():
    """Test basic port scanning"""
    print("🔴 RedScan AI - Scanner Test")
    print("=" * 60)
    
    # Safe target to scan (official Nmap test server)
    target = "scanme.nmap.org"
    
    print(f"\n[*] Target: {target}")
    print("[*] This is a safe, authorized target for testing\n")
    
    # Initialize scanner
    scanner = NetworkScanner(target)
    
    # Scan common ports (faster for testing)
    print("[*] Scanning common ports (20-25, 80, 443, 8080)...")
    test_ports = list(range(20, 26)) + [80, 443, 8080]
    open_ports = scanner.scan_ports(port_range=test_ports, max_workers=10)
    
    print(f"\n[+] Found {len(open_ports)} open ports")
    
    # Banner grabbing
    if open_ports:
        print("\n[*] Attempting banner grabbing...")
        for port in open_ports[:3]:  # Test first 3 ports
            banner = scanner.banner_grab(port)
            if banner:
                print(f"[+] Port {port} banner: {banner[:100]}...")
    
    # Vulnerability scanning
    print("\n[*] Running vulnerability checks...")
    vuln_scanner = VulnerabilityScanner(target, open_ports)
    vulnerabilities = vuln_scanner.check_common_vulnerabilities()
    
    print(f"[+] Found {len(vulnerabilities)} potential issues")
    for vuln in vulnerabilities:
        print(f"    - {vuln['title']} [{vuln['severity'].upper()}]")
    
    # Risk score
    risk_score = vuln_scanner.calculate_risk_score()
    print(f"\n[*] Overall Risk Score: {risk_score:.2f}/10")
    
    # Recon features
    print("\n[*] Testing reconnaissance features...")
    ip = scanner.resolve_hostname()
    print(f"[+] Resolved IP: {ip}")
    
    print("\n✅ Test complete!")
    print("\nNext: Integrate this into Django by running scans through the web interface")

if __name__ == '__main__':
    test_basic_scan()
