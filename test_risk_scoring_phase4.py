"""
Phase 4 Risk Scoring System Test
Tests CVSS calculation, attack chain detection, and AI risk prediction
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rescanai.cvss_calculator import calculate_cvss
from rescanai.attack_chain_detector import detect_attack_chains
from rescanai.risk_predictor import predict_vulnerability_risk
from rescanai.risk_analyzer import RiskAnalyzer


def test_cvss_scoring():
    """Test CVSS v3.1 scoring"""
    print("\n" + "="*70)
    print("PHASE 4 TEST: CVSS v3.1 Scoring")
    print("="*70)
    
    test_vulns = [
        'SQL Injection',
        'Stored XSS',
        'Command Injection',
        'Missing Security Header',
        'Default Credentials',
    ]
    
    for vuln_type in test_vulns:
        result = calculate_cvss(vuln_type)
        print(f"\n📊 {vuln_type}:")
        print(f"   Score: {result['base_score']} ({result['severity']})")
        print(f"   Vector: {result['vector_string']}")
        print(f"   Exploitability: {result['exploitability_score']}")
        print(f"   Impact: {result['impact_score']}")


def test_attack_chain_detection():
    """Test attack chain detection"""
    print("\n" + "="*70)
    print("PHASE 4 TEST: Attack Chain Detection")
    print("="*70)
    
    # Simulate vulnerabilities that form attack chains
    test_vulns = [
        {'type': 'SQL Injection', 'severity': 'Critical', 'cvss_score': 9.8},
        {'type': 'Admin Panel Exposed', 'severity': 'Medium', 'cvss_score': 5.3},
        {'type': 'XSS Vulnerability', 'severity': 'High', 'cvss_score': 7.1},
        {'type': 'Weak Session Management', 'severity': 'Medium', 'cvss_score': 5.9},
        {'type': 'Missing Security Headers', 'severity': 'Low', 'cvss_score': 4.0},
    ]
    
    chains = detect_attack_chains(test_vulns)
    
    print(f"\n🔗 Detected {len(chains)} attack chain(s):\n")
    
    for chain in chains:
        print(f"Chain: {chain['chain_name']}")
        print(f"  Severity: {chain['severity']}")
        print(f"  Risk Multiplier: {chain['risk_multiplier']}x")
        print(f"  Base Risk: {chain['base_risk_score']}")
        print(f"  Amplified Risk: {chain['amplified_risk_score']}")
        print(f"  Description: {chain['description']}")
        print(f"  Vulnerabilities: {chain['vulnerability_count']}")
        print()


def test_ai_risk_prediction():
    """Test AI-based risk prediction"""
    print("\n" + "="*70)
    print("PHASE 4 TEST: AI-Based Risk Prediction")
    print("="*70)
    
    # Test vulnerability with different contexts
    vuln = {
        'type': 'SQL Injection',
        'severity': 'Critical',
        'cvss_score': 9.8
    }
    
    contexts = [
        {
            'target_type': 'production',
            'exposure': 'internet-facing',
            'data_sensitivity': 'pii'
        },
        {
            'target_type': 'development',
            'exposure': 'internal',
            'data_sensitivity': 'public'
        }
    ]
    
    for i, context in enumerate(contexts, 1):
        print(f"\n🤖 Test Context {i}: {context}")
        prediction = predict_vulnerability_risk(vuln, context)
        
        print(f"   Base Score: {prediction['base_risk_score']}")
        print(f"   Predicted Score: {prediction['predicted_risk_score']}")
        print(f"   Confidence: {prediction['confidence']}")
        print(f"   Priority: {prediction['priority']}")
        print(f"   Recommendation: {prediction['recommendation']}")
        print(f"   Risk Factors:")
        for factor, value in prediction['risk_factors'].items():
            print(f"     - {factor}: {value}")


def test_integrated_risk_analyzer():
    """Test integrated risk analyzer with Phase 4 features"""
    print("\n" + "="*70)
    print("PHASE 4 TEST: Integrated Risk Analysis")
    print("="*70)
    
    # Simulate comprehensive scan results
    scan_results = {
        'target': 'test.example.com',
        'target_type': 'production',
        'exposure': 'internet-facing',
        'data_sensitivity': 'pii',
        'vulnerabilities': [
            {'type': 'SQL Injection', 'severity': 'Critical'},
            {'type': 'Admin Panel Exposed', 'severity': 'Medium'},
            {'type': 'XSS Stored', 'severity': 'High'},
            {'type': 'Weak Session Management', 'severity': 'Medium'},
            {'type': 'Missing CSP Header', 'severity': 'Low'},
            {'type': 'MySQL Port Open', 'severity': 'High'},
        ],
        'ports': [80, 443, 3306, 8080],
        'web_data': {}
    }
    
    analyzer = RiskAnalyzer()
    breakdown = analyzer.generate_risk_breakdown(scan_results, scan_type='comprehensive')
    
    print(f"\n📈 Risk Breakdown:")
    print(f"   Base Risk Score: {breakdown['base_risk_score']}")
    print(f"   Chain Amplification: {breakdown['chain_amplification_factor']}x")
    print(f"   Final Risk Score: {breakdown['final_risk_score']}")
    print(f"   Risk Level: {breakdown['risk_level'].upper()}")
    print(f"   Vulnerabilities: {breakdown['vulnerability_count']}")
    
    print(f"\n   CVSS Analysis:")
    cvss = breakdown['cvss_analysis']
    print(f"     Average CVSS: {cvss['average_cvss_score']}")
    print(f"     Critical: {cvss['critical_count']}")
    print(f"     High: {cvss['high_count']}")
    print(f"     Medium: {cvss['medium_count']}")
    print(f"     Low: {cvss['low_count']}")
    
    print(f"\n   Attack Chains:")
    chains = breakdown['attack_chains']
    print(f"     Detected: {chains['detected_count']}")
    print(f"     Critical Chains: {chains['critical_chains']}")
    
    print(f"\n   AI Predictions:")
    ai = breakdown['ai_predictions']
    print(f"     Immediate Priority: {ai['immediate_priority_count']}")
    print(f"     Urgent Priority: {ai['urgent_priority_count']}")
    print(f"     High Priority: {ai['high_priority_count']}")
    
    print(f"\n   Top 3 Risks:")
    for i, risk in enumerate(breakdown['top_risks'][:3], 1):
        print(f"     {i}. {risk['type']}")
        print(f"        CVSS: {risk['cvss_score']} | Predicted: {risk['predicted_score']}")
        print(f"        Priority: {risk['priority']}")
    
    print(f"\n   Recommendations:")
    for rec in breakdown['recommendations'][:5]:
        print(f"     • {rec}")


def main():
    """Run all Phase 4 tests"""
    print("\n" + "="*70)
    print("🚀 RedScan AI - Phase 4 Risk Scoring System Tests")
    print("="*70)
    
    try:
        test_cvss_scoring()
        test_attack_chain_detection()
        test_ai_risk_prediction()
        test_integrated_risk_analyzer()
        
        print("\n" + "="*70)
        print("✅ ALL PHASE 4 TESTS COMPLETED SUCCESSFULLY!")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
