#!/usr/bin/env python3
"""
Test script to verify progress never exceeds 100%
"""
import sys
import os
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redscan.settings')
django.setup()

from rescanai.scan_controller import ScanController


def test_progress_cap():
    """Test that progress never exceeds 100%"""
    print("🔍 Testing Progress Cap Fix")
    print("=" * 50)
    
    target = "httpbin.org"
    max_progress = 0
    progress_values = []
    
    def progress_callback(progress, message):
        """Track all progress values"""
        nonlocal max_progress
        max_progress = max(max_progress, progress)
        progress_values.append(progress)
        print(f"[{progress:3d}%] {message}")
    
    print(f"🎯 Target: {target}")
    print("🚀 Starting scan to test progress cap...")
    print()
    
    try:
        controller = ScanController(
            target=target,
            scan_type='quick',
            progress_callback=progress_callback
        )
        
        # Run scan with all options
        results = controller.execute_scan({
            'quick_common_ports': True,
            'quick_header_analysis': True,
            'quick_basic_sqli': True,
            'quick_basic_xss': True
        })
        
        print()
        print("📊 Progress Analysis:")
        print(f"   Maximum Progress: {max_progress}%")
        print(f"   Total Progress Updates: {len(progress_values)}")
        print(f"   Progress Range: {min(progress_values)}% - {max(progress_values)}%")
        print()
        
        # Check if progress exceeded 100%
        if max_progress <= 100:
            print("✅ SUCCESS: Progress never exceeded 100%")
            print("   The 103% bug has been FIXED!")
        else:
            print(f"❌ FAILED: Progress reached {max_progress}%")
            print("   The bug still exists")
        
        # Show any values over 100%
        over_100 = [p for p in progress_values if p > 100]
        if over_100:
            print(f"   Values over 100%: {over_100}")
        else:
            print("   No values exceeded 100% ✅")
        
        print()
        print("📈 Scan Results:")
        print(f"   Ports found: {len(results.get('ports', []))}")
        print(f"   Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        
        return max_progress <= 100
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False


if __name__ == "__main__":
    success = test_progress_cap()
    
    print()
    print("=" * 50)
    if success:
        print("🎉 PROGRESS FIX VERIFIED!")
        print("   No more 103% progress bug!")
    else:
        print("⚠️  Progress fix may need more work")
    print("=" * 50)