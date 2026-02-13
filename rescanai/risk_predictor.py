"""
AI-Based Risk Predictor Module
Provides intelligent risk assessment using pattern-based analysis
Context-aware scoring for better vulnerability prioritization
"""

from typing import Dict, List
import time


class RiskPredictor:
    """
    AI-Based Risk Prediction Engine
    Uses pattern analysis and context-aware scoring for intelligent risk assessment
    """
    
    def __init__(self):
        # Vulnerability type risk weights (injection > XSS > misconfig)
        self.vuln_type_weights = {
            'sql injection': 1.0,
            'command injection': 1.0,
            'code injection': 0.95,
            'authentication bypass': 0.95,
            'remote code execution': 1.0,
            'xss': 0.75,
            'csrf': 0.70,
            'path traversal': 0.80,
            'file upload': 0.85,
            'security misconfiguration': 0.60,
            'missing security header': 0.50,
            'information disclosure': 0.55,
            'ssl/tls issue': 0.65,
            'weak password': 0.75,
            'default credentials': 0.85
        }
        
        # Target context weights (production > staging > dev)
        self.context_weights = {
            'production': 1.2,
            'staging': 0.9,
            'development': 0.7,
            'testing': 0.6,
            'unknown': 1.0
        }
        
        # Exposure level weights (internet > internal)
        self.exposure_weights = {
            'internet-facing': 1.3,
            'public': 1.3,
            'dmz': 1.1,
            'internal': 0.8,
            'isolated': 0.5,
            'localhost': 0.3,
            'unknown': 1.0
        }
        
        # Data sensitivity weights
        self.sensitivity_weights = {
            'pii': 1.3,  # Personally Identifiable Information
            'financial': 1.4,
            'health': 1.4,
            'credentials': 1.3,
            'business_critical': 1.2,
            'internal': 0.9,
            'public': 0.6,
            'unknown': 1.0
        }
    
    def predict_risk(self, vulnerability: Dict, context: Dict = None) -> Dict:
        """
        Predict comprehensive risk assessment for a vulnerability
        
        Args:
            vulnerability: Vulnerability details (type, severity, cvss_score, etc.)
            context: Optional context (target_type, exposure, data_sensitivity)
            
        Returns:
            Dict with predicted_score, confidence, factors, recommendation
        """
        context = context or {}
        
        # Get base risk score
        base_score = vulnerability.get('cvss_score', vulnerability.get('severity_score', 5.0))
        
        # Apply pattern-based adjustments
        vuln_type_factor = self._get_vulnerability_type_factor(vulnerability)
        context_factor = self._get_context_factor(context)
        exposure_factor = self._get_exposure_factor(context)
        sensitivity_factor = self._get_sensitivity_factor(context)
        
        # Calculate exploitability prediction
        exploitability = self._predict_exploitability(vulnerability, context)
        
        # Combine all factors
        total_multiplier = (
            vuln_type_factor *
            context_factor *
            exposure_factor *
            sensitivity_factor *
            exploitability
        )
        
        # Calculate predicted risk score
        predicted_score = min(10.0, base_score * total_multiplier)
        
        # Calculate confidence level
        confidence = self._calculate_confidence(vulnerability, context)
        
        # Generate risk factors explanation
        factors = {
            'vulnerability_type_factor': round(vuln_type_factor, 2),
            'context_factor': round(context_factor, 2),
            'exposure_factor': round(exposure_factor, 2),
            'sensitivity_factor': round(sensitivity_factor, 2),
            'exploitability': round(exploitability, 2),
            'total_multiplier': round(total_multiplier, 2)
        }
        
        # Determine priority
        priority = self._assign_priority(predicted_score, confidence)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(vulnerability, predicted_score, factors)
        
        return {
            'predicted_risk_score': round(predicted_score, 1),
            'base_risk_score': round(base_score, 1),
            'confidence': confidence,
            'priority': priority,
            'risk_factors': factors,
            'recommendation': recommendation,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _get_vulnerability_type_factor(self, vulnerability: Dict) -> float:
        """Get risk factor based on vulnerability type"""
        vuln_type = vulnerability.get('type', '').lower()
        
        # Check against known patterns
        for pattern, weight in self.vuln_type_weights.items():
            if pattern in vuln_type:
                return weight
        
        # Default based on severity
        severity = vulnerability.get('severity', '').lower()
        severity_defaults = {
            'critical': 1.0,
            'high': 0.85,
            'medium': 0.70,
            'low': 0.50,
            'info': 0.30
        }
        return severity_defaults.get(severity, 0.75)
    
    def _get_context_factor(self, context: Dict) -> float:
        """Get risk factor based on target context"""
        target_type = context.get('target_type', 'unknown').lower()
        
        for ctx, weight in self.context_weights.items():
            if ctx in target_type:
                return weight
        
        return self.context_weights['unknown']
    
    def _get_exposure_factor(self, context: Dict) -> float:
        """Get risk factor based on exposure level"""
        exposure = context.get('exposure', 'unknown').lower()
        
        for exp, weight in self.exposure_weights.items():
            if exp in exposure:
                return weight
        
        return self.exposure_weights['unknown']
    
    def _get_sensitivity_factor(self, context: Dict) -> float:
        """Get risk factor based on data sensitivity"""
        sensitivity = context.get('data_sensitivity', 'unknown').lower()
        
        for sens, weight in self.sensitivity_weights.items():
            if sens in sensitivity:
                return weight
        
        return self.sensitivity_weights['unknown']
    
    def _predict_exploitability(self, vulnerability: Dict, context: Dict) -> float:
        """
        Predict exploitability based on various factors
        Returns multiplier between 0.5 and 1.5
        """
        exploitability_score = 1.0
        
        # Check if exploit is publicly available
        if vulnerability.get('exploit_available'):
            exploitability_score *= 1.3
        
        # Check attack complexity
        attack_complexity = vulnerability.get('attack_complexity', 'unknown').lower()
        if 'low' in attack_complexity:
            exploitability_score *= 1.2
        elif 'high' in attack_complexity:
            exploitability_score *= 0.8
        
        # Check if authentication is required
        auth_required = vulnerability.get('authentication_required', False)
        if not auth_required:
            exploitability_score *= 1.15
        
        # Check user interaction
        user_interaction = vulnerability.get('user_interaction', 'unknown').lower()
        if 'none' in user_interaction:
            exploitability_score *= 1.1
        
        return min(1.5, max(0.5, exploitability_score))
    
    def _calculate_confidence(self, vulnerability: Dict, context: Dict) -> str:
        """
        Calculate confidence level in the risk prediction
        Returns: 'High', 'Medium', 'Low'
        """
        confidence_score = 0
        
        # More info = higher confidence
        if vulnerability.get('cvss_score'):
            confidence_score += 2
        if vulnerability.get('type'):
            confidence_score += 1
        if vulnerability.get('severity'):
            confidence_score += 1
        if context.get('target_type'):
            confidence_score += 1
        if context.get('exposure'):
            confidence_score += 1
        
        if confidence_score >= 5:
            return 'High'
        elif confidence_score >= 3:
            return 'Medium'
        else:
            return 'Low'
    
    def _assign_priority(self, predicted_score: float, confidence: str) -> str:
        """
        Assign remediation priority
        Returns: 'Critical', 'High', 'Medium', 'Low'
        """
        # Adjust based on confidence
        if confidence == 'High':
            if predicted_score >= 9.0:
                return 'Critical'
            elif predicted_score >= 7.0:
                return 'High'
            elif predicted_score >= 4.0:
                return 'Medium'
            else:
                return 'Low'
        else:
            # Lower priority if low confidence
            if predicted_score >= 9.5:
                return 'Critical'
            elif predicted_score >= 8.0:
                return 'High'
            elif predicted_score >= 5.0:
                return 'Medium'
            else:
                return 'Low'
    
    def _generate_recommendation(self, vulnerability: Dict, predicted_score: float, factors: Dict) -> str:
        """Generate intelligent remediation recommendation"""
        vuln_type = vulnerability.get('type', 'vulnerability')
        priority = self._assign_priority(predicted_score, 'High')
        
        # Build recommendation based on factors
        recommendations = []
        
        if predicted_score >= 9.0:
            recommendations.append(f"URGENT: Address this {vuln_type} immediately")
        elif predicted_score >= 7.0:
            recommendations.append(f"HIGH PRIORITY: Fix this {vuln_type}  within 7 days")
        else:
            recommendations.append(f"Schedule remediation for this {vuln_type}")
        
        # Add context-specific recommendations
        if factors['exposure_factor'] > 1.2:
            recommendations.append("Priority increased due to internet exposure")
        
        if factors['sensitivity_factor'] > 1.2:
            recommendations.append("Handles sensitive data - requires immediate attention")
        
        if factors['exploitability'] > 1.2:
            recommendations.append("Highly exploitable - active monitoring recommended")
        
        return '. '.join(recommendations)
    
    def batch_predict(self, vulnerabilities: List[Dict], context: Dict = None) -> List[Dict]:
        """
        Predict risk for multiple vulnerabilities at once
        Returns sorted list by predicted risk (highest first)
        """
        predictions = []
        
        for vuln in vulnerabilities:
            prediction = self.predict_risk(vuln, context)
            prediction['original_vulnerability'] = vuln
            predictions.append(prediction)
        
        # Sort by predicted risk score (descending)
        predictions.sort(key=lambda x: x['predicted_risk_score'], reverse=True)
        
        return predictions


# Convenience function
def predict_vulnerability_risk(vulnerability: Dict, context: Dict = None) -> Dict:
    """
    Quick risk prediction
    
    Example:
        vuln = {'type': 'SQL injection', 'severity': 'Critical', 'cvss_score': 9.8}
        context = {'exposure': 'internet-facing', 'data_sensitivity': 'pii'}
        result = predict_vulnerability_risk(vuln, context)
    """
    predictor = RiskPredictor()
    return predictor.predict_risk(vulnerability, context)
