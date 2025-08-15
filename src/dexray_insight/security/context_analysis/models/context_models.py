#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum

class CodeLocation(Enum):
    """Types of code locations where secrets might be found"""
    SOURCE_CODE = "source_code"
    CONFIGURATION_FILE = "configuration_file"
    RESOURCE_FILE = "resource_file"
    BUILD_SCRIPT = "build_script"
    TEST_CODE = "test_code"
    DOCUMENTATION = "documentation"
    COMMENT = "comment"
    STRING_LITERAL = "string_literal"
    XML_ATTRIBUTE = "xml_attribute"
    JSON_VALUE = "json_value"
    UNKNOWN = "unknown"

class ProtectionLevel(Enum):
    """Levels of protection applied to secrets"""
    NONE = "none"                    # No protection (plaintext)
    OBFUSCATION = "obfuscation"     # Simple obfuscation (base64, etc.)
    ENCRYPTION = "encryption"        # Encrypted storage
    ENVIRONMENT = "environment"      # Environment variables
    SECURE_STORAGE = "secure_storage" # Android KeyStore, iOS Keychain
    RUNTIME_INJECTION = "runtime_injection" # Injected at runtime
    BUILD_TIME_INJECTION = "build_time_injection" # Injected at build time

@dataclass
class CodeContext:
    """
    Represents the code context surrounding a detected secret.
    
    This class captures information about the immediate code environment
    where a secret was detected, including variables, methods, classes,
    and patterns that help determine the secret's purpose and risk level.
    """
    location_type: CodeLocation = CodeLocation.UNKNOWN
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    surrounding_lines: List[str] = field(default_factory=list)
    variable_names: Set[str] = field(default_factory=set)
    method_signatures: List[str] = field(default_factory=list)
    class_names: Set[str] = field(default_factory=set)
    package_names: Set[str] = field(default_factory=set)
    imports: Set[str] = field(default_factory=set)
    annotations: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    protection_level: ProtectionLevel = ProtectionLevel.NONE
    
    def has_test_indicators(self) -> bool:
        """Check if the context indicates this is test code"""
        test_indicators = {
            'test', 'mock', 'stub', 'fake', 'dummy', 'junit', 'testng', 
            'espresso', 'robolectric', 'mockito'
        }
        
        # Check file path for test directories and specific patterns
        if self.file_path:
            path_lower = self.file_path.lower()
            # Check for test directories
            if '/test/' in path_lower or '/tests/' in path_lower:
                return True
            # Check for test file patterns (but be more specific than just any occurrence)
            if any(f'{indicator}.' in path_lower or f'{indicator}_' in path_lower 
                   for indicator in test_indicators):
                return True
            # Check for file names ending with Test
            if path_lower.endswith('test.java') or path_lower.endswith('tests.java'):
                return True
        
        # Check class names
        for class_name in self.class_names:
            if any(indicator in class_name.lower() for indicator in test_indicators):
                return True
        
        # Check method signatures
        for method in self.method_signatures:
            if any(indicator in method.lower() for indicator in test_indicators):
                return True
        
        # Check imports
        for import_stmt in self.imports:
            if any(indicator in import_stmt.lower() for indicator in test_indicators):
                return True
        
        return False
    
    def has_configuration_indicators(self) -> bool:
        """Check if the context indicates this is configuration data"""
        config_indicators = {
            'config', 'settings', 'properties', 'constants', 'defaults',
            'environment', 'env', 'build', 'gradle', 'maven'
        }
        
        # Check file path
        if self.file_path:
            path_lower = self.file_path.lower()
            if any(indicator in path_lower for indicator in config_indicators):
                return True
        
        # Check variable names
        for var_name in self.variable_names:
            if any(indicator in var_name.lower() for indicator in config_indicators):
                return True
        
        return False
    
    def get_encryption_indicators(self) -> List[str]:
        """Get indicators that suggest encryption/security measures are in use"""
        encryption_keywords = {
            'encrypt', 'decrypt', 'cipher', 'aes', 'rsa', 'sha', 'md5',
            'keystore', 'keychain', 'secret', 'secure', 'crypto', 'ssl', 'tls'
        }
        
        indicators = []
        
        # Check imports
        for import_stmt in self.imports:
            if any(keyword in import_stmt.lower() for keyword in encryption_keywords):
                indicators.append(f"Crypto import: {import_stmt}")
        
        # Check method signatures
        for method in self.method_signatures:
            if any(keyword in method.lower() for keyword in encryption_keywords):
                indicators.append(f"Crypto method: {method}")
        
        # Check surrounding lines
        for line in self.surrounding_lines:
            if any(keyword in line.lower() for keyword in encryption_keywords):
                indicators.append(f"Crypto code: {line[:50]}...")
        
        return indicators
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'location_type': self.location_type.value,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'surrounding_lines': self.surrounding_lines,
            'variable_names': list(self.variable_names),
            'method_signatures': self.method_signatures,
            'class_names': list(self.class_names),
            'package_names': list(self.package_names),
            'imports': list(self.imports),
            'annotations': self.annotations,
            'comments': self.comments,
            'protection_level': self.protection_level.value,
            'has_test_indicators': self.has_test_indicators(),
            'has_configuration_indicators': self.has_configuration_indicators(),
            'encryption_indicators': self.get_encryption_indicators()
        }

@dataclass
class RiskContext:
    """
    Represents risk-related context derived from correlation with other analysis results.
    
    This class captures risk indicators from behavior analysis, API usage,
    permissions, and other security factors that help assess the actual
    security impact of a detected secret.
    """
    network_usage_detected: bool = False
    privileged_api_usage: bool = False
    external_service_communication: bool = False
    permission_escalation_potential: bool = False
    data_exfiltration_risk: bool = False
    correlated_behavior_patterns: List[str] = field(default_factory=list)
    related_api_calls: List[str] = field(default_factory=list)
    suspicious_permissions: List[str] = field(default_factory=list)
    risk_multipliers: Dict[str, float] = field(default_factory=dict)
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on various factors"""
        base_score = 0.5  # Base risk score
        
        # Network usage increases risk
        if self.network_usage_detected:
            base_score += 0.2
        
        # Privileged API usage significantly increases risk
        if self.privileged_api_usage:
            base_score += 0.3
        
        # External communication is a major risk factor
        if self.external_service_communication:
            base_score += 0.25
        
        # Permission escalation potential is critical
        if self.permission_escalation_potential:
            base_score += 0.4
        
        # Data exfiltration risk is the highest concern
        if self.data_exfiltration_risk:
            base_score += 0.5
        
        # Apply risk multipliers
        for factor, multiplier in self.risk_multipliers.items():
            base_score *= multiplier
        
        # Ensure score stays within bounds
        return min(1.0, max(0.0, base_score))
    
    def get_primary_risk_factors(self) -> List[str]:
        """Get the primary risk factors contributing to this context"""
        factors = []
        
        if self.data_exfiltration_risk:
            factors.append("Data exfiltration potential")
        if self.permission_escalation_potential:
            factors.append("Permission escalation risk")
        if self.external_service_communication:
            factors.append("External service communication")
        if self.privileged_api_usage:
            factors.append("Privileged API usage")
        if self.network_usage_detected:
            factors.append("Network communication")
        
        return factors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'network_usage_detected': self.network_usage_detected,
            'privileged_api_usage': self.privileged_api_usage,
            'external_service_communication': self.external_service_communication,
            'permission_escalation_potential': self.permission_escalation_potential,
            'data_exfiltration_risk': self.data_exfiltration_risk,
            'correlated_behavior_patterns': self.correlated_behavior_patterns,
            'related_api_calls': self.related_api_calls,
            'suspicious_permissions': self.suspicious_permissions,
            'risk_multipliers': self.risk_multipliers,
            'risk_score': self.calculate_risk_score(),
            'primary_risk_factors': self.get_primary_risk_factors()
        }

@dataclass
class FalsePositiveIndicator:
    """
    Represents an indicator that suggests a finding might be a false positive.
    
    This class captures specific patterns, contexts, or characteristics that
    commonly indicate false positive detections in mobile applications.
    """
    indicator_type: str
    indicator_value: str
    confidence: float  # 0.0 = low confidence, 1.0 = high confidence
    description: str
    source: str  # Where this indicator was detected (e.g., 'code_analysis', 'pattern_matching')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'confidence': self.confidence,
            'description': self.description,
            'source': self.source
        }