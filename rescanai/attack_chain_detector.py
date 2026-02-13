"""
Attack Chain Detector Module
Identifies critical vulnerability combinations that create attack chains
Examples: SQLi + admin access, XSS + weak sessions, etc.
"""

from typing import List, Dict, Tuple
import hashlib


class AttackChainDetector:
    """
    Detects attack chains - combinations of vulnerabilities that amplify risk
    """
    
    def __init__(self):
        # Define attack chain patterns
        self.chain_patterns = self._initialize_chain_patterns()
        
    def _initialize_chain_patterns(self) -> List[Dict]:
        """
        Define known attack chain patterns
        Each pattern specifies vulnerability combinations and their risk multiplier
        """
        return [
            {
                'name': 'SQL Injection + Admin Access',
                'pattern': ['sql injection', 'admin'],
                'severity': 'Critical',
                'risk_multiplier': 3.0,
                'description': 'SQL injection vulnerability combined with access to admin functionality allows complete system compromise',
                'attack_scenario': 'Attacker can use SQL injection to bypass authentication and gain full administrative control'
            },
            {
                'name': 'SQL Injection + Database Exposure',
                'pattern': ['sql injection', 'database', 'exposed'],
                'severity': 'Critical',
                'risk_multiplier': 2.5,
                'description': 'SQL injection with exposed database port allows direct data exfiltration',
                'attack_scenario': 'Attacker can extract sensitive data directly from the exposed database'
            },
            {
                'name': 'XSS + Weak Session Management',
                'pattern': ['xss', 'session'],
                'severity': 'High',
                'risk_multiplier': 2.0,
                'description': 'XSS vulnerability with weak session management enables session hijacking',
                'attack_scenario': 'Attacker can steal session tokens via XSS and impersonate users'
            },
            {
                'name': 'XSS + Missing Security Headers',
                'pattern': ['xss', 'security header'],
                'severity': 'High',
                'risk_multiplier': 1.8,
                'description': 'XSS with missing CSP headers makes exploitation easier',
                'attack_scenario': 'Lack of Content-Security-Policy allows unrestricted XSS payload execution'
            },
            {
                'name': 'Command Injection + Admin Access',
                'pattern': ['command injection', 'admin'],
                'severity': 'Critical',
                'risk_multiplier': 3.0,
                'description': 'Command injection in admin context allows full system takeover',
                'attack_scenario': 'Attacker can execute arbitrary commands with administrative privileges'
            },
            {
                'name': 'Authentication Bypass + Sensitive Data',
                'pattern': ['authentication', 'database'],
                'severity': 'Critical',
                'risk_multiplier': 2.5,
                'description': 'Weak authentication protecting sensitive database access',
                'attack_scenario': 'Attacker can bypass weak auth to access sensitive database'
            },
            {
                'name': 'File Upload + Code Execution',
                'pattern': ['file upload', 'execution'],
                'severity': 'Critical',
                'risk_multiplier': 2.8,
                'description': 'Unrestricted file upload allowing code execution',
                'attack_scenario': 'Attacker uploads malicious scripts that get executed on server'
            },
            {
                'name': 'CSRF + Privileged Operations',
                'pattern': ['csrf', 'admin'],
                'severity': 'High',
                'risk_multiplier': 2.0,
                'description': 'CSRF vulnerability affecting privileged operations',
                'attack_scenario': 'Attacker tricks admin into performing unauthorized actions'
            },
            {
                'name': 'Open Database + No Authentication',
                'pattern': ['database', 'exposed', 'authentication'],
                'severity': 'Critical',
                'risk_multiplier': 2.5,
                'description': 'Database accessible without authentication',
                'attack_scenario': 'Direct unauthorized access to database without credentials'
            },
            {
                'name': 'Path Traversal + Sensitive Files',
                'pattern': ['path traversal', 'file'],
                'severity': 'High',
                'risk_multiplier': 2.0,
                'description': 'Path traversal allowing access to sensitive system files',
                'attack_scenario': 'Attacker can read configuration files, credentials, or source code'
            },
            {
                'name': 'Injection + Debug Mode',
                'pattern': ['injection', 'debug'],
                'severity': 'Critical',
                'risk_multiplier': 2.2,
                'description': 'Injection vulnerability with debug mode exposing detailed errors',
                'attack_scenario': 'Debug information aids attacker in crafting precise injection payloads'
            },
            {
                'name': 'Multiple High-Severity Issues',
                'pattern': ['critical', 'critical'],  # Two critical vulns
                'severity': 'Critical',
                'risk_multiplier': 1.5,
                'description': 'Multiple critical vulnerabilities present',
                'attack_scenario': 'Multiple attack vectors available for system compromise'
            }
        ]
    
    def detect_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Detect attack chains from list of vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts with 'type', 'severity', etc.
            
        Returns:
            List of detected attack chains with details and risk amplification
        """
        if not vulnerabilities or len(vulnerabilities) < 2:
            return []
        
        detected_chains = []
        
        # Check each chain pattern
        for pattern in self.chain_patterns:
            chain = self._check_pattern(pattern, vulnerabilities)
            if chain:
                detected_chains.append(chain)
        
        # Check for multiple critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        if len(critical_vulns) >= 2:
            chain = self._create_multiple_critical_chain(critical_vulns)
            detected_chains.append(chain)
        
        # Deduplicate chains
        detected_chains = self._deduplicate_chains(detected_chains)
        
        return detected_chains
    
    def _check_pattern(self, pattern: Dict, vulnerabilities: List[Dict]) -> Dict:
        """Check if a specific attack chain pattern exists"""
        pattern_keywords = pattern['pattern']
        matching_vulns = []
        
        # Find vulnerabilities matching this pattern
        for vuln in vulnerabilities:
            vuln_desc = self._get_vuln_description(vuln).lower()
            
            # Check if any pattern keyword matches
            for keyword in pattern_keywords:
                if keyword in vuln_desc:
                    matching_vulns.append(vuln)
                    break
        
        # Need at least 2 matching vulnerabilities for a chain
        if len(matching_vulns) >= 2:
            # Calculate amplified risk score
            base_scores = [v.get('cvss_score', v.get('severity_score', 5.0)) for v in matching_vulns]
            avg_base_score = sum(base_scores) / len(base_scores)
            amplified_score = min(10.0, avg_base_score * pattern['risk_multiplier'])
            
            # Generate unique chain ID
            chain_id = self._generate_chain_id(pattern['name'], matching_vulns)
            
            return {
                'chain_id': chain_id,
                'chain_name': pattern['name'],
                'severity': pattern['severity'],
                'risk_multiplier': pattern['risk_multiplier'],
                'base_risk_score': round(avg_base_score, 1),
                'amplified_risk_score': round(amplified_score, 1),
                'description': pattern['description'],
                'attack_scenario': pattern['attack_scenario'],
                'vulnerabilities': matching_vulns,
                'vulnerability_count': len(matching_vulns)
            }
        
        return None
    
    def _create_multiple_critical_chain(self, critical_vulns: List[Dict]) -> Dict:
        """Create chain for multiple critical vulnerabilities"""
        base_scores = [v.get('cvss_score', 9.0) for v in critical_vulns]
        avg_score = sum(base_scores) / len(base_scores)
        amplified_score = min(10.0, avg_score * 1.5)
        
        chain_id = self._generate_chain_id('Multiple Critical', critical_vulns)
        
        return {
            'chain_id': chain_id,
            'chain_name': f'{len(critical_vulns)} Critical Vulnerabilities',
            'severity': 'Critical',
            'risk_multiplier': 1.5,
            'base_risk_score': round(avg_score, 1),
            'amplified_risk_score': round(amplified_score, 1),
            'description': f'System has {len(critical_vulns)} critical vulnerabilities creating multiple attack vectors',
            'attack_scenario': 'Multiple critical vulnerabilities provide redundant attack paths for system compromise',
            'vulnerabilities': critical_vulns,
            'vulnerability_count': len(critical_vulns)
        }
    
    def _get_vuln_description(self, vuln: Dict) -> str:
        """Get full description of vulnerability for pattern matching"""
        parts = [
            vuln.get('type', ''),
            vuln.get('title', ''),
            vuln.get('description', ''),
            vuln.get('severity', '')
        ]
        return ' '.join(filter(None, parts))
    
    def _generate_chain_id(self, chain_name: str, vulns: List[Dict]) -> str:
        """Generate unique ID for an attack chain"""
        # Create hash from chain name and vulnerability IDs
        vuln_ids = sorted([str(v.get('id', v.get('type', ''))) for v in vulns])
        hash_input = f"{chain_name}:{'|'.join(vuln_ids)}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]
    
    def _deduplicate_chains(self, chains: List[Dict]) -> List[Dict]:
        """Remove duplicate attack chains"""
        seen_ids = set()
        unique_chains = []
        
        for chain in chains:
            chain_id = chain['chain_id']
            if chain_id not in seen_ids:
                seen_ids.add(chain_id)
                unique_chains.append(chain)
        
        return unique_chains
    
    def get_critical_attack_paths(self, chains: List[Dict]) -> List[Dict]:
        """
        Identify the most critical attack paths from detected chains
        Returns chains sorted by risk (highest first)
        """
        critical_chains = [c for c in chains if c['severity'] == 'Critical']
        critical_chains.sort(key=lambda x: x['amplified_risk_score'], reverse=True)
        return critical_chains
    
    def calculate_chain_priority(self, chain: Dict) -> str:
        """
        Calculate remediation priority for an attack chain
        Returns: 'Immediate', 'Urgent', 'High', 'Medium', 'Low'
        """
        score = chain['amplified_risk_score']
        severity = chain['severity']
        
        if severity == 'Critical' and score >= 9.0:
            return 'Immediate'
        elif severity == 'Critical' or score >= 8.0:
            return 'Urgent'
        elif score >= 7.0:
            return 'High'
        elif score >= 5.0:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_chain_recommendations(self, chains: List[Dict]) -> List[str]:
        """Generate remediation recommendations for detected attack chains"""
        recommendations = []
        
        # Sort by priority
        sorted_chains = sorted(chains, key=lambda x: x['amplified_risk_score'], reverse=True)
        
        for chain in sorted_chains:
            priority = self.calculate_chain_priority(chain)
            recommendations.append(
                f"[{priority}] {chain['chain_name']}: {chain['description']}"
            )
        
        # Add general recommendations
        if chains:
            recommendations.append(
                "Attack chains significantly increase exploitation risk. "
                "Address vulnerabilities in critical chains as highest priority."
            )
        
        return recommendations


# Convenience function
def detect_attack_chains(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Quick attack chain detection
    
    Example:
        vulns = [
            {'type': 'SQL Injection', 'severity': 'Critical'},
            {'type': 'Admin Panel Exposed', 'severity': 'Medium'}
        ]
        chains = detect_attack_chains(vulns)
    """
    detector = AttackChainDetector()
    return detector.detect_chains(vulnerabilities)
