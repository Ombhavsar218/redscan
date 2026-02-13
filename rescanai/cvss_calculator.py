"""
CVSS v3.1 Calculator Module
Implements Common Vulnerability Scoring System version 3.1
Provides accurate vulnerability scoring with vector string generation
"""

from typing import Dict, Tuple, Optional
from enum import Enum


class CVSSv31:
    """
    CVSS v3.1 Base Score Calculator
    Reference: https://www.first.org/cvss/v3.1/specification-document
    """
    
    # Attack Vector (AV)
    AV_NETWORK = 0.85
    AV_ADJACENT = 0.62
    AV_LOCAL = 0.55
    AV_PHYSICAL = 0.2
    
    # Attack Complexity (AC)
    AC_LOW = 0.77
    AC_HIGH = 0.44
    
    # Privileges Required (PR)
    PR_NONE = 0.85
    PR_LOW = 0.62  # when Scope is Unchanged
    PR_LOW_CHANGED = 0.68  # when Scope is Changed
    PR_HIGH = 0.27  # when Scope is Unchanged
    PR_HIGH_CHANGED = 0.50  # when Scope is Changed
    
    # User Interaction (UI)
    UI_NONE = 0.85
    UI_REQUIRED = 0.62
    
    # Scope (S)
    SCOPE_UNCHANGED = 'U'
    SCOPE_CHANGED = 'C'
    
    # Confidentiality Impact (C)
    IMPACT_NONE = 0.0
    IMPACT_LOW = 0.22
    IMPACT_HIGH = 0.56
    
    # Integrity Impact (I)
    # Same as Confidentiality
    
    # Availability Impact (A)
    # Same as Confidentiality
    
    def __init__(self):
        self.metrics = {}
        
    def calculate_base_score(self, 
                            attack_vector: str,
                            attack_complexity: str,
                            privileges_required: str,
                            user_interaction: str,
                            scope: str,
                            confidentiality: str,
                            integrity: str,
                            availability: str) -> Dict:
        """
        Calculate CVSS v3.1 Base Score
        
        Args:
            attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
            attack_complexity: L (Low), H (High)
            privileges_required: N (None), L (Low), H (High)
            user_interaction: N (None), R (Required)
            scope: U (Unchanged), C (Changed)
            confidentiality: N (None), L (Low), H (High)
            integrity: N (None), L (Low), H (High)
            availability: N (None), L (Low), H (High)
            
        Returns:
            Dict with base_score, exploitability_score, impact_score, vector_string
        """
        
        # Get metric values
        av_value = self._get_av_value(attack_vector)
        ac_value = self._get_ac_value(attack_complexity)
        pr_value = self._get_pr_value(privileges_required, scope)
        ui_value = self._get_ui_value(user_interaction)
        
        c_value = self._get_impact_value(confidentiality)
        i_value = self._get_impact_value(integrity)
        a_value = self._get_impact_value(availability)
        
        # Calculate Impact Sub-Score
        isc_base = 1 - ((1 - c_value) * (1 - i_value) * (1 - a_value))
        
        if scope == 'U':
            impact = 6.42 * isc_base
        else:  # Scope Changed
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Calculate Exploitability Sub-Score
        exploitability = 8.22 * av_value * ac_value * pr_value * ui_value
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if scope == 'U':
                base_score = min(10.0, impact + exploitability)
            else:
                base_score = min(10.0, 1.08 * (impact + exploitability))
        
        # Round to one decimal
        base_score = round(base_score, 1)
        impact = round(impact, 1)
        exploitability = round(exploitability, 1)
        
        # Generate vector string
        vector = self._generate_vector_string(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality, integrity, availability
        )
        
        # Determine severity rating
        severity = self._get_severity_rating(base_score)
        
        return {
            'base_score': base_score,
            'impact_score': impact,
            'exploitability_score': exploitability,
            'vector_string': vector,
            'severity': severity
        }
    
    def _get_av_value(self, av: str) -> float:
        """Get Attack Vector value"""
        return {
            'N': self.AV_NETWORK,
            'A': self.AV_ADJACENT,
            'L': self.AV_LOCAL,
            'P': self.AV_PHYSICAL
        }.get(av.upper(), self.AV_NETWORK)
    
    def _get_ac_value(self, ac: str) -> float:
        """Get Attack Complexity value"""
        return {
            'L': self.AC_LOW,
            'H': self.AC_HIGH
        }.get(ac.upper(), self.AC_LOW)
    
    def _get_pr_value(self, pr: str, scope: str) -> float:
        """Get Privileges Required value"""
        pr = pr.upper()
        if pr == 'N':
            return self.PR_NONE
        elif pr == 'L':
            return self.PR_LOW_CHANGED if scope == 'C' else self.PR_LOW
        elif pr == 'H':
            return self.PR_HIGH_CHANGED if scope == 'C' else self.PR_HIGH
        return self.PR_NONE
    
    def _get_ui_value(self, ui: str) -> float:
        """Get User Interaction value"""
        return {
            'N': self.UI_NONE,
            'R': self.UI_REQUIRED
        }.get(ui.upper(), self.UI_NONE)
    
    def _get_impact_value(self, impact: str) -> float:
        """Get Impact value (C/I/A)"""
        return {
            'N': self.IMPACT_NONE,
            'L': self.IMPACT_LOW,
            'H': self.IMPACT_HIGH
        }.get(impact.upper(), self.IMPACT_NONE)
    
    def _generate_vector_string(self, av, ac, pr, ui, s, c, i, a) -> str:
        """Generate CVSS v3.1 vector string"""
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    
    def _get_severity_rating(self, score: float) -> str:
        """Convert numeric score to severity rating"""
        if score == 0.0:
            return 'None'
        elif score < 4.0:
            return 'Low'
        elif score < 7.0:
            return 'Medium'
        elif score < 9.0:
            return 'High'
        else:
            return 'Critical'
    
    def calculate_for_vulnerability_type(self, vuln_type: str, context: Dict = None) -> Dict:
        """
        Calculate CVSS score based on vulnerability type
        Provides intelligent defaults based on common vulnerability patterns
        
        Args:
            vuln_type: Type of vulnerability (e.g., 'SQL Injection', 'XSS', etc.)
            context: Additional context (target_type, exposure, etc.)
        """
        vuln_type_lower = vuln_type.lower()
        context = context or {}
        
        # Default CVSS metrics for common vulnerability types
        if 'sql injection' in vuln_type_lower or 'sqli' in vuln_type_lower:
            return self.calculate_base_score(
                attack_vector='N',      # Network accessible
                attack_complexity='L',  # Low complexity
                privileges_required='N', # No privileges needed
                user_interaction='N',    # No user interaction
                scope='C',              # Scope changed (can access DB)
                confidentiality='H',    # High - can read all data
                integrity='H',          # High - can modify data
                availability='H'        # High - can delete/crash DB
            )
        
        elif 'xss' in vuln_type_lower or 'cross-site scripting' in vuln_type_lower:
            if 'stored' in vuln_type_lower:
                return self.calculate_base_score(
                    attack_vector='N',
                    attack_complexity='L',
                    privileges_required='L',  # Usually needs to post
                    user_interaction='R',     # User must visit page
                    scope='C',
                    confidentiality='L',
                    integrity='L',
                    availability='N'
                )
            else:  # Reflected XSS
                return self.calculate_base_score(
                    attack_vector='N',
                    attack_complexity='L',
                    privileges_required='N',
                    user_interaction='R',
                    scope='C',
                    confidentiality='L',
                    integrity='L',
                    availability='N'
                )
        
        elif 'command injection' in vuln_type_lower or 'rce' in vuln_type_lower:
            return self.calculate_base_score(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='C',
                confidentiality='H',
                integrity='H',
                availability='H'
            )
        
        elif 'authentication' in vuln_type_lower or 'default credentials' in vuln_type_lower:
            return self.calculate_base_score(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='H',
                availability='H'
            )
        
        elif 'path traversal' in vuln_type_lower or 'directory traversal' in vuln_type_lower:
            return self.calculate_base_score(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='N',
                availability='N'
            )
        
        elif 'security header' in vuln_type_lower or 'missing header' in vuln_type_lower:
            return self.calculate_base_score(
                attack_vector='N',
                attack_complexity='H',
                privileges_required='N',
                user_interaction='R',
                scope='U',
                confidentiality='L',
                integrity='L',
                availability='N'
            )
        
        elif 'ssl' in vuln_type_lower or 'tls' in vuln_type_lower or 'certificate' in vuln_type_lower:
            return self.calculate_base_score(
                attack_vector='N',
                attack_complexity='H',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='N',
                availability='N'
            )
        
        elif 'open port' in vuln_type_lower or 'exposed service' in vuln_type_lower:
            # Risk varies by service
            if any(db in vuln_type_lower for db in ['mysql', 'postgresql', 'mongodb', 'redis']):
                return self.calculate_base_score(
                    attack_vector='N',
                    attack_complexity='L',
                    privileges_required='N',
                    user_interaction='N',
                    scope='C',
                    confidentiality='H',
                    integrity='H',
                    availability='H'
                )
            else:
                return self.calculate_base_score(
                    attack_vector='N',
                    attack_complexity='L',
                    privileges_required='N',
                    user_interaction='N',
                    scope='U',
                    confidentiality='L',
                    integrity='N',
                    availability='N'
                )
        
        else:
            # Default medium severity
            return self.calculate_base_score(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='L',
                user_interaction='N',
                scope='U',
                confidentiality='L',
                integrity='L',
                availability='N'
            )


# Convenience function for quick calculations
def calculate_cvss(vuln_type: str, context: Dict = None) -> Dict:
    """
    Quick CVSS calculation for a vulnerability type
    
    Example:
        result = calculate_cvss('SQL Injection')
        print(f"Score: {result['base_score']} ({result['severity']})")
        print(f"Vector: {result['vector_string']}")
    """
    calculator = CVSSv31()
    return calculator.calculate_for_vulnerability_type(vuln_type, context)
