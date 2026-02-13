"""
Risk Analyzer Module - Calculates risk scores and generates recommendations
Provides comprehensive risk assessment for different scan types
Phase 4 Enhancement: Integrated CVSS v3.1, Attack Chain Detection, and AI-based Risk Prediction
"""

from typing import Dict, List, Any
import math

# Phase 4: Import new risk scoring modules
from .cvss_calculator import CVSSv31, calculate_cvss
from .attack_chain_detector import AttackChainDetector, detect_attack_chains
from .risk_predictor import RiskPredictor, predict_vulnerability_risk


class RiskAnalyzer:
    """
    Enhanced Risk Analyzer Module (Phase 4)
    Features:
    - CVSS v3.1 vulnerability scoring
    - Attack chain detection
    - AI-based risk prediction
    - Comprehensive risk assessment for different scan types
    """
    
    def __init__(self):
        # Severity weights for risk calculation (0-100 scale)
        self.severity_weights = {
            'critical': 30.0,  # Critical vulnerabilities contribute heavily
            'high': 20.0,      # High vulnerabilities are significant  
            'medium': 10.0,    # Medium vulnerabilities are moderate
            'low': 5.0,        # Low vulnerabilities are minor
            'info': 1.0        # Info vulnerabilities are minimal
        }
        
        # Risk level thresholds (0-100 scale)
        self.risk_levels = {
            'low': (0, 20),        # 0-20 = Low Risk
            'medium': (21, 50),    # 21-50 = Medium Risk  
            'high': (51, 80),      # 51-80 = High Risk
            'critical': (81, 100)  # 81-100 = Critical Risk
        }
        
        # Phase 4: Initialize new risk scoring modules
        self.cvss_calculator = CVSSv31()
        self.chain_detector = AttackChainDetector()
        self.risk_predictor = RiskPredictor()
    
    def calculate_quick_scan_risk(self, results: Dict[str, Any]) -> float:
        """
        Calculate risk score for Quick Scan results
        Focuses on immediate security concerns
        """
        risk_score = 0.0
        
        # Base risk from vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            risk_score += self.severity_weights.get(severity, 2.0)
        
        # Additional risk factors for Quick Scan
        
        # Open ports risk
        open_ports = results.get('ports', [])
        if len(open_ports) > 10:
            risk_score += 1.0  # Many open ports increase attack surface
        
        # Web service specific risks
        web_data = results.get('web_data', {})
        
        # Header analysis risk
        if 'headers' in web_data:
            header_data = web_data['headers']
            missing_headers = header_data.get('missing_headers', [])
            
            # Critical security headers missing
            critical_headers = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security']
            missing_critical = [h for h in missing_headers if h in critical_headers]
            risk_score += len(missing_critical) * 0.5
        
        # SQLi risk amplification
        if 'sqli' in web_data:
            sqli_vulns = web_data['sqli'].get('vulnerabilities', [])
            if sqli_vulns:
                risk_score += 2.0  # SQLi is always serious
        
        # XSS risk amplification
        if 'xss' in web_data:
            xss_vulns = web_data['xss'].get('vulnerabilities', [])
            if xss_vulns:
                risk_score += 1.0  # XSS increases risk
        
        # Normalize to 0-100 scale
        return min(100.0, risk_score)
    
    def calculate_comprehensive_risk(self, results: Dict[str, Any]) -> float:
        """
        Calculate comprehensive risk score for Full Scan results
        """
        risk_score = 0.0
        
        # Base vulnerability risk
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            risk_score += self.severity_weights.get(severity, 2.0)
        
        # Port-based risk assessment
        open_ports = results.get('ports', [])
        services = results.get('services', {})
        
        # High-risk services
        high_risk_services = ['telnet', 'ftp', 'mysql', 'postgresql', 'mongodb']
        for port in open_ports:
            service = services.get(port, '').lower()
            if service in high_risk_services:
                risk_score += 1.5
        
        # Many open ports
        if len(open_ports) > 20:
            risk_score += 2.0
        elif len(open_ports) > 10:
            risk_score += 1.0
        
        # Web application risks
        web_data = results.get('web_data', {})
        if web_data:
            risk_score += self._calculate_web_risk_component(web_data)
        
        # API risks
        api_data = results.get('api_data', {})
        if api_data:
            risk_score += self._calculate_api_risk_component(api_data)
        
        return min(100.0, risk_score)
    
    def calculate_web_risk(self, results: Dict[str, Any]) -> float:
        """
        Calculate risk score for Web Scan results
        """
        risk_score = 0.0
        
        # Base vulnerability risk
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            risk_score += self.severity_weights.get(severity, 2.0)
        
        # Web-specific risk calculation
        web_data = results.get('web_data', {})
        risk_score += self._calculate_web_risk_component(web_data)
        
        return min(100.0, risk_score)
    
    def calculate_vulnerability_risk(self, results: Dict[str, Any]) -> float:
        """
        Calculate risk score for Vulnerability Scan results
        """
        risk_score = 0.0
        
        # Vulnerability scans focus heavily on found vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Weight vulnerabilities more heavily for vulnerability scans
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            weight = self.severity_weights.get(severity, 2.0)
            risk_score += weight * 1.5  # 1.5x multiplier for vulnerability scans
        
        # Additional risk from specific vulnerability types
        vuln_types = [vuln.get('type', '').lower() for vuln in vulnerabilities]
        
        if any('sql injection' in vtype for vtype in vuln_types):
            risk_score += 3.0  # SQL injection is critical
        
        if any('authentication' in vtype for vtype in vuln_types):
            risk_score += 2.0  # Auth issues are serious
        
        if any('command injection' in vtype for vtype in vuln_types):
            risk_score += 3.0  # Command injection is critical
        
        return min(100.0, risk_score)
    
    def calculate_localhost_risk(self, results: Dict[str, Any]) -> float:
        """
        Calculate risk score for Localhost Scan results
        """
        risk_score = 0.0
        
        # Base vulnerability risk
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            risk_score += self.severity_weights.get(severity, 2.0)
        
        # Localhost-specific risks
        localhost_data = results.get('localhost_data', {})
        
        # Django-specific risks
        django_data = localhost_data.get('django', {})
        if django_data.get('detected'):
            django_issues = django_data.get('issues', [])
            risk_score += len(django_issues) * 0.5
        
        # Development server risks
        dev_servers = localhost_data.get('dev_servers', {}).get('servers', [])
        risk_score += len(dev_servers) * 0.3  # Each dev server adds some risk
        
        # Container risks
        containers = localhost_data.get('containers', {}).get('containers', [])
        for container in containers:
            if container.get('port') == 2375:  # Insecure Docker API
                risk_score += 3.0
            else:
                risk_score += 0.5
        
        return min(100.0, risk_score)
    
    def calculate_custom_risk(self, results: Dict[str, Any]) -> float:
        """
        Calculate risk score for Custom Scan results
        """
        # Use comprehensive risk calculation as base
        return self.calculate_comprehensive_risk(results)
    
    def _calculate_web_risk_component(self, web_data: Dict[str, Any]) -> float:
        """Calculate risk component from web data"""
        risk = 0.0
        
        # Header analysis
        if 'headers' in web_data:
            header_data = web_data['headers']
            missing_headers = header_data.get('missing_headers', [])
            weak_headers = header_data.get('weak_headers', [])
            
            risk += len(missing_headers) * 0.3
            risk += len(weak_headers) * 0.2
        
        # SQL injection
        if 'sqli' in web_data:
            sqli_vulns = web_data['sqli'].get('vulnerabilities', [])
            risk += len(sqli_vulns) * 2.0
        
        # XSS
        if 'xss' in web_data:
            xss_vulns = web_data['xss'].get('vulnerabilities', [])
            risk += len(xss_vulns) * 1.5
        
        # Crawling results
        if 'crawl' in web_data:
            crawl_data = web_data['crawl']
            errors = crawl_data.get('errors', [])
            risk += len(errors) * 0.1
        
        return risk
    
    def _calculate_api_risk_component(self, api_data: Dict[str, Any]) -> float:
        """Calculate risk component from API data"""
        risk = 0.0
        
        # API discovery
        if 'discovery' in api_data:
            discovery = api_data['discovery']
            exposed_apis = discovery.get('discovered_apis', [])
            risk += len(exposed_apis) * 0.2
        
        # Authentication issues
        if 'authentication' in api_data:
            auth_data = api_data['authentication']
            auth_vulns = auth_data.get('vulnerabilities', [])
            risk += len(auth_vulns) * 1.5
        
        # Data exposure
        if 'data_exposure' in api_data:
            exposure_data = api_data['data_exposure']
            exposed_endpoints = exposure_data.get('exposed_endpoints', [])
            risk += len(exposed_endpoints) * 1.0
        
        return risk
    
    def get_risk_level(self, risk_score: float) -> str:
        """
        Get risk level category based on score
        """
        for level, (min_score, max_score) in self.risk_levels.items():
            if min_score <= risk_score < max_score:
                return level
        
        return 'critical' if risk_score >= 8 else 'minimal'
    
    def generate_quick_scan_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations for Quick Scan results
        """
        recommendations = []
        
        vulnerabilities = results.get('vulnerabilities', [])
        web_data = results.get('web_data', {})
        
        # General recommendations based on vulnerabilities
        vuln_types = [vuln.get('type', '').lower() for vuln in vulnerabilities]
        
        if any('sql injection' in vtype for vtype in vuln_types):
            recommendations.append("🔴 CRITICAL: Fix SQL injection vulnerabilities immediately using parameterized queries")
        
        if any('xss' in vtype for vtype in vuln_types):
            recommendations.append("🟠 HIGH: Implement proper input validation and output encoding to prevent XSS attacks")
        
        if any('header' in vtype for vtype in vuln_types):
            recommendations.append("🟡 MEDIUM: Add missing security headers to improve web application security")
        
        # Header-specific recommendations
        if 'headers' in web_data:
            missing_headers = web_data['headers'].get('missing_headers', [])
            
            if 'Content-Security-Policy' in missing_headers:
                recommendations.append("Add Content-Security-Policy header to prevent XSS and data injection attacks")
            
            if 'X-Frame-Options' in missing_headers:
                recommendations.append("Add X-Frame-Options header to prevent clickjacking attacks")
            
            if 'Strict-Transport-Security' in missing_headers:
                recommendations.append("Add HSTS header to enforce HTTPS connections")
        
        # Port-based recommendations
        open_ports = results.get('ports', [])
        if 80 in open_ports and 443 not in open_ports:
            recommendations.append("Consider implementing HTTPS to encrypt web traffic")
        
        if len(open_ports) > 10:
            recommendations.append("Review open ports and close unnecessary services to reduce attack surface")
        
        # Default recommendations if no specific issues found
        if not recommendations:
            recommendations.extend([
                "✅ No critical vulnerabilities found in quick scan",
                "Consider running a full scan for comprehensive security assessment",
                "Regularly update software and security patches",
                "Implement monitoring and logging for security events"
            ])
        
        return recommendations
    
    def generate_comprehensive_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate comprehensive recommendations for Full Scan results
        """
        recommendations = []
        
        # Start with quick scan recommendations
        recommendations.extend(self.generate_quick_scan_recommendations(results))
        
        # Add comprehensive-specific recommendations
        services = results.get('services', {})
        
        # Service-specific recommendations
        for port, service in services.items():
            if service.lower() == 'telnet':
                recommendations.append(f"🔴 CRITICAL: Replace Telnet (port {port}) with SSH for secure remote access")
            
            elif service.lower() == 'ftp':
                recommendations.append(f"🟠 HIGH: Consider replacing FTP (port {port}) with SFTP or FTPS")
            
            elif service.lower() in ['mysql', 'postgresql']:
                recommendations.append(f"🟠 HIGH: Secure database service on port {port} - restrict access and use strong authentication")
        
        # API-specific recommendations
        api_data = results.get('api_data', {})
        if api_data:
            recommendations.extend(self._generate_api_recommendations(api_data))
        
        return list(set(recommendations))  # Remove duplicates
    
    def generate_web_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations for Web Scan results
        """
        recommendations = []
        
        web_data = results.get('web_data', {})
        
        # Technology-specific recommendations
        if 'technologies' in web_data:
            tech_data = web_data['technologies']
            
            # CMS recommendations
            cms_list = tech_data.get('cms', [])
            for cms in cms_list:
                recommendations.append(f"Keep {cms} updated to the latest version to prevent known vulnerabilities")
            
            # Framework recommendations
            frameworks = tech_data.get('frameworks', [])
            for framework in frameworks:
                recommendations.append(f"Ensure {framework} is configured securely and updated regularly")
        
        # Crawling-based recommendations
        if 'crawl' in web_data:
            crawl_data = web_data['crawl']
            pages = crawl_data.get('pages', [])
            
            if len(pages) > 50:
                recommendations.append("Large web application detected - consider implementing proper access controls")
        
        # Add base web recommendations
        recommendations.extend(self.generate_quick_scan_recommendations(results))
        
        return list(set(recommendations))
    
    def generate_vulnerability_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations for Vulnerability Scan results
        """
        recommendations = []
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Prioritize recommendations by severity
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        
        if critical_vulns:
            recommendations.append(f"🔴 URGENT: Address {len(critical_vulns)} critical vulnerabilities immediately")
        
        if high_vulns:
            recommendations.append(f"🟠 HIGH PRIORITY: Fix {len(high_vulns)} high-severity vulnerabilities")
        
        # Specific vulnerability type recommendations
        vuln_types = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        for vtype, count in vuln_types.items():
            if 'sql injection' in vtype.lower():
                recommendations.append("Implement parameterized queries and input validation to prevent SQL injection")
            elif 'xss' in vtype.lower():
                recommendations.append("Implement proper output encoding and Content Security Policy")
            elif 'authentication' in vtype.lower():
                recommendations.append("Strengthen authentication mechanisms and remove default credentials")
        
        # General security recommendations
        recommendations.extend([
            "Implement a vulnerability management program",
            "Regular security testing and code reviews",
            "Keep all software components updated",
            "Implement security monitoring and incident response"
        ])
        
        return recommendations
    
    def generate_localhost_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations for Localhost Scan results
        """
        recommendations = []
        
        localhost_data = results.get('localhost_data', {})
        
        # Django-specific recommendations
        if 'django' in localhost_data and localhost_data['django'].get('detected'):
            recommendations.extend([
                "Ensure Django DEBUG mode is disabled in production",
                "Review Django security settings and middleware",
                "Implement proper Django authentication and authorization",
                "Keep Django and dependencies updated"
            ])
        
        # Development server recommendations
        dev_servers = localhost_data.get('dev_servers', {}).get('servers', [])
        if dev_servers:
            recommendations.extend([
                "Development servers detected - ensure they're not exposed in production",
                "Use proper production web servers (Apache, Nginx) for live environments",
                "Implement proper security configurations for production deployment"
            ])
        
        # Container recommendations
        containers = localhost_data.get('containers', {}).get('containers', [])
        if containers:
            recommendations.extend([
                "Secure container configurations and remove unnecessary exposures",
                "Implement container security best practices",
                "Regular container image updates and vulnerability scanning"
            ])
        
        return recommendations
    
    def _generate_api_recommendations(self, api_data: Dict[str, Any]) -> List[str]:
        """Generate API-specific recommendations"""
        recommendations = []
        
        # Authentication recommendations
        if 'authentication' in api_data:
            auth_vulns = api_data['authentication'].get('vulnerabilities', [])
            if auth_vulns:
                recommendations.append("Implement strong API authentication (OAuth 2.0, JWT)")
                recommendations.append("Remove or change default API credentials")
        
        # Data exposure recommendations
        if 'data_exposure' in api_data:
            exposed = api_data['data_exposure'].get('exposed_endpoints', [])
            if exposed:
                recommendations.append("Implement proper API access controls and data filtering")
                recommendations.append("Review API endpoints for sensitive data exposure")
        
        # CORS recommendations
        if 'cors_testing' in api_data:
            cors_vulns = api_data['cors_testing'].get('vulnerabilities', [])
            if cors_vulns:
                recommendations.append("Configure CORS policy properly - avoid wildcard origins")
        
        # Rate limiting recommendations
        if 'rate_limiting' in api_data:
            if not api_data['rate_limiting'].get('rate_limiting_detected'):
                recommendations.append("Implement API rate limiting to prevent abuse")
        
        return recommendations
    
    # ========================================================================
    # PHASE 4: Enhanced Risk Scoring Methods
    # ========================================================================
    
    def calculate_cvss_scores(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Calculate CVSS v3.1 scores for all vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Enhanced vulnerability list with CVSS scores
        """
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            # Calculate CVSS score based on vulnerability type
            cvss_result = self.cvss_calculator.calculate_for_vulnerability_type(
                vuln_type=vuln.get('type', 'Unknown'),
                context=vuln.get('context', {})
            )
            
            # Add CVSS data to vulnerability
            vuln['cvss_score'] = cvss_result['base_score']
            vuln['cvss_vector'] = cvss_result['vector_string']
            vuln['cvss_exploitability_score'] = cvss_result['exploitability_score']
            vuln['cvss_impact_score'] = cvss_result['impact_score']
            vuln['cvss_severity'] = cvss_result['severity']
            
            enhanced_vulns.append(vuln)
        
        return enhanced_vulns
    
    def detect_attack_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Detect attack chains from vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities with CVSS scores
            
        Returns:
            List of detected attack chains
        """
        return self.chain_detector.detect_chains(vulnerabilities)
    
    def predict_risks(self, vulnerabilities: List[Dict], context: Dict = None) -> List[Dict]:
        """
        Apply AI-based risk prediction to vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities
            context: Scanning context (target_type, exposure, etc.)
            
        Returns:
            Vulnerabilities with AI risk predictions
        """
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            # Get AI risk prediction
            prediction = self.risk_predictor.predict_risk(vuln, context)
            vuln['risk_prediction'] = prediction
            enhanced_vulns.append(vuln)
        
        return enhanced_vulns
    
    def generate_risk_breakdown(self, results: Dict[str, Any], scan_type: str = 'comprehensive') -> Dict:
        """
        Generate comprehensive risk breakdown with Phase 4 enhancements
        
        Args:
            results: Scan results dictionary
            scan_type: Type of scan performed
            
        Returns:
            Detailed risk breakdown with CVSS, attack chains, and predictions
        """
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Step 1: Calculate CVSS scores for all vulnerabilities
        vulns_with_cvss = self.calculate_cvss_scores(vulnerabilities)
        
        # Step 2: Detect attack chains
        attack_chains = self.detect_attack_chains(vulns_with_cvss)
        
        # Step 3: Apply AI risk prediction
        context = {
            'target_type': results.get('target_type', 'unknown'),
            'exposure': results.get('exposure', 'unknown'),
            'data_sensitivity': results.get('data_sensitivity', 'unknown')
        }
        vulns_with_prediction = self.predict_risks(vulns_with_cvss, context)
        
        # Step 4: Calculate overall risk score
        if scan_type == 'quick':
            base_risk = self.calculate_quick_scan_risk(results)
        elif scan_type == 'web':
            base_risk = self.calculate_web_risk(results)
        elif scan_type == 'localhost':
            base_risk = self.calculate_localhost_risk(results)
        elif scan_type == 'vulnerability':
            base_risk = self.calculate_vulnerability_risk(results)
        else:
            base_risk = self.calculate_comprehensive_risk(results)
        
        # Apply attack chain amplification
        chain_amplification = 1.0
        if attack_chains:
            max_chain_multiplier = max([c['risk_multiplier'] for c in attack_chains])
            chain_amplification = max_chain_multiplier
        
        amplified_risk = min(10.0, base_risk * chain_amplification)
        
        # Determine risk level
        risk_level = self.get_risk_level(amplified_risk)
        
        # Build comprehensive breakdown
        breakdown = {
            'base_risk_score': round(base_risk, 1),
            'chain_amplification_factor': round(chain_amplification, 2),
            'final_risk_score': round(amplified_risk, 1),
            'risk_level': risk_level,
            'vulnerability_count': len(vulnerabilities),
            'cvss_analysis': {
                'average_cvss_score': round(sum([v.get('cvss_score', 0) for v in vulns_with_cvss]) / max(len(vulns_with_cvss), 1), 1),
                'critical_count': len([v for v in vulns_with_cvss if v.get('cvss_severity') == 'Critical']),
                'high_count': len([v for v in vulns_with_cvss if v.get('cvss_severity') == 'High']),
                'medium_count': len([v for v in vulns_with_cvss if v.get('cvss_severity') == 'Medium']),
                'low_count': len([v for v in vulns_with_cvss if v.get('cvss_severity') == 'Low'])
            },
            'attack_chains': {
                'detected_count': len(attack_chains),
                'critical_chains': len([c for c in attack_chains if c['severity'] == 'Critical']),
                'chains': attack_chains
            },
            'ai_predictions': {
                'immediate_priority_count': len([v for v in vulns_with_prediction if v.get('risk_prediction', {}).get('priority') == 'Critical']),
                'urgent_priority_count': len([v for v in vulns_with_prediction if v.get('risk_prediction', {}).get('priority') == 'Urgent']),
                'high_priority_count': len([v for v in vulns_with_prediction if v.get('risk_prediction', {}).get('priority') == 'High'])
            },
            'top_risks': self._get_top_risks(vulns_with_prediction, limit=5),
            'recommendations': self._generate_enhanced_recommendations(vulns_with_prediction, attack_chains)
        }
        
        return breakdown
    
    def _get_top_risks(self, vulnerabilities: List[Dict], limit: int = 5) -> List[Dict]:
        """Get top N vulnerabilities by predicted risk"""
        # Sort by predicted risk score
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.get('risk_prediction', {}).get('predicted_risk_score', 0),
            reverse=True
        )
        
        top_risks = []
        for vuln in sorted_vulns[:limit]:
            prediction = vuln.get('risk_prediction', {})
            top_risks.append({
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'Unknown'),
                'cvss_score': vuln.get('cvss_score', 0),
                'predicted_score': prediction.get('predicted_risk_score', 0),
                'priority': prediction.get('priority', 'Unknown'),
                'recommendation': prediction.get('recommendation', '')
            })
        
        return top_risks
    
    def _generate_enhanced_recommendations(self, vulnerabilities: List[Dict], attack_chains: List[Dict]) -> List[str]:
        """Generate enhanced recommendations with Phase 4 insights"""
        recommendations = []
        
        # Attack chain recommendations (highest priority)
        if attack_chains:
            critical_chains = [c for c in attack_chains if c['severity'] == 'Critical']
            if critical_chains:
                recommendations.append(
                    f"🔴 CRITICAL: {len(critical_chains)} attack chain(s) detected! "
                    f"These vulnerability combinations create immediate security risks."
                )
                for chain in critical_chains[:3]:  # Top 3
                    recommendations.append(
                        f"  ⚠️ {chain['chain_name']}: {chain['description']}"
                    )
        
        # CVSS-based recommendations
        critical_vulns = [v for v in vulnerabilities if v.get('cvss_severity') == 'Critical']
        if critical_vulns:
            recommendations.append(
                f"🔴 {len(critical_vulns)} Critical CVSS vulnerabilities require immediate attention"
            )
        
        # AI prediction recommendations
        immediate_vulns = [v for v in vulnerabilities 
                          if v.get('risk_prediction', {}).get('priority') == 'Critical']
        if immediate_vulns:
            recommendations.append(
                f"🚨 AI analysis identified {len(immediate_vulns)} vulnerabilities requiring immediate action"
            )
        
        # Add specific vulnerability recommendations
        for vuln in vulnerabilities[:5]:  # Top 5 vulns
            prediction = vuln.get('risk_prediction', {})
            if prediction.get('predicted_risk_score', 0) >= 8.0:
                recommendations.append(prediction.get('recommendation', ''))
        
        return list(filter(None, recommendations))  # Remove empty strings
    def generate_custom_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations for Custom Scan results
        """
        recommendations = []
        
        # Port-based recommendations
        open_ports = results.get('ports', [])
        if open_ports:
            recommendations.append(f"Review {len(open_ports)} open ports and close unnecessary services")
            
            # High-risk ports
            high_risk_ports = [p for p in open_ports if p in [21, 23, 135, 139, 445, 1433, 3389, 5900]]
            if high_risk_ports:
                recommendations.append(f"High-risk ports detected: {high_risk_ports} - consider additional security measures")
            
            # Database ports
            db_ports = [p for p in open_ports if p in [3306, 5432, 1521, 1433]]
            if db_ports:
                recommendations.append("Database ports exposed - ensure proper access controls and encryption")
        
        # Web service recommendations
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
        if web_ports:
            recommendations.extend([
                "Web services detected - ensure HTTPS is properly configured",
                "Implement security headers and proper authentication",
                "Regular security testing and vulnerability assessments"
            ])
        
        # General security recommendations
        recommendations.extend([
            "Implement network segmentation and firewall rules",
            "Regular security monitoring and log analysis",
            "Keep all services updated with latest security patches",
            "Conduct regular penetration testing"
        ])
        
        return recommendations