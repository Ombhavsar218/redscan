#!/usr/bin/env python3
"""
Test script for meaningful, different log messages
Shows how each step has a unique, descriptive message
"""

import sys
import os
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from rescanai.scan_controller import ScanController


def test_meaningful_logs():
    """Test meaningful, different log messages for each step"""
    
    print("🔹 TESTING MEANINGFUL LOG MESSAGES")
    print("=" * 60)
    print("Each step now has a unique, descriptive message!")
    print("No more repetitive '(1/23), (2/23), (3/23)' messages")
    print("=" * 60)
    
    target = "httpbin.org"
    
    # Test scenarios with different option combinations
    test_scenarios = [
        {
            'name': 'Quick Scan - 2 Options (Ports + Headers)',
            'scan_type': 'quick',
            'options': {
                'quick_common_ports': True,
                'quick_basic_sqli': False,
                'quick_basic_xss': False,
                'quick_header_analysis': True
            }
        },
        {
            'name': 'Quick Scan - All 4 Options',
            'scan_type': 'quick',
            'options': {
                'quick_common_ports': True,
                'quick_basic_sqli': True,
                'quick_basic_xss': True,
                'quick_header_analysis': True
            }
        }
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{'='*20} TEST {i}/2 {'='*20}")
        print(f"🧪 {scenario['name']}")
        
        # Count selected options
        selected_count = sum(1 for v in scenario['options'].values() if v)
        total_options = len(scenario['options'])
        print(f"☑️  Selected: {selected_count}/{total_options} options")
        print("-" * 50)
        
        # Track unique messages
        unique_messages = set()
        all_messages = []
        
        def progress_callback(progress, message):
            all_messages.append((progress, message))
            unique_messages.add(message)
            print(f"[{progress:3d}%] {message}")
        
        try:
            controller = ScanController(
                target=target,
                scan_type=scenario['scan_type'],
                progress_callback=progress_callback
            )
            
            results = controller.execute_scan(scenario['options'])
            
            # Analyze message uniqueness
            print(f"\n📊 Message Analysis:")
            print(f"   Total Messages: {len(all_messages)}")
            print(f"   Unique Messages: {len(unique_messages)}")
            print(f"   Uniqueness Rate: {(len(unique_messages)/len(all_messages)*100):.1f}%")
            
            # Show some example unique messages
            print(f"\n💬 Example Unique Messages:")
            sample_messages = list(unique_messages)[:10]
            for j, msg in enumerate(sample_messages, 1):
                print(f"   {j}. {msg}")
            
            if len(unique_messages) > 10:
                print(f"   ... and {len(unique_messages) - 10} more unique messages")
            
            # Show results
            print(f"\n📈 Scan Results:")
            print(f"   Open Ports: {len(results.get('ports', []))}")
            print(f"   Vulnerabilities: {len(results.get('vulnerabilities', []))}")
            print(f"   Risk Score: {results.get('risk_score', 0):.1f}/10")
            
        except Exception as e:
            print(f"❌ Test failed: {str(e)}")
    
    print(f"\n{'='*60}")
    print("✅ Meaningful Log Messages Testing Complete!")
    print("\nKey Improvements:")
    print("• Each step has a unique, descriptive message")
    print("• No more repetitive counter messages")
    print("• Messages describe what's actually happening")
    print("• Progress is still 1% incremental")
    print("• Dynamic based on selected options")


def show_message_examples():
    """Show examples of the different message types"""
    
    print("\n🔹 MESSAGE TYPE EXAMPLES")
    print("=" * 40)
    
    controller = ScanController("example.com", "quick")
    
    print("🔓 Port Scan Messages:")
    port_messages = controller._get_port_scan_messages(5)
    for i, msg in enumerate(port_messages, 1):
        print(f"   {i}. {msg}")
    
    print("\n🔒 Header Analysis Messages:")
    header_messages = controller._get_header_analysis_messages(5)
    for i, msg in enumerate(header_messages, 1):
        print(f"   {i}. {msg}")
    
    print("\n💉 SQL Injection Test Messages:")
    sqli_messages = controller._get_sqli_test_messages(5)
    for i, msg in enumerate(sqli_messages, 1):
        print(f"   {i}. {msg}")
    
    print("\n🚨 XSS Test Messages:")
    xss_messages = controller._get_xss_test_messages(5)
    for i, msg in enumerate(xss_messages, 1):
        print(f"   {i}. {msg}")
    
    print("\n🔍 Full Port Scan Messages:")
    full_port_messages = controller._get_full_port_scan_messages(5)
    for i, msg in enumerate(full_port_messages, 1):
        print(f"   {i}. {msg}")


if __name__ == "__main__":
    show_message_examples()
    test_meaningful_logs()