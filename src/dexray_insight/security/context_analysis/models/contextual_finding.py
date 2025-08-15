#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

class ContextConfidence(Enum):
    """Confidence levels for contextual analysis results"""
    VERY_LOW = "very_low"    # 0-20% confidence
    LOW = "low"              # 21-40% confidence  
    MEDIUM = "medium"        # 41-60% confidence
    HIGH = "high"            # 61-80% confidence
    VERY_HIGH = "very_high"  # 81-100% confidence

class SecretUsageType(Enum):
    """Types of secret usage patterns detected in code"""
    HARDCODED_CONSTANT = "hardcoded_constant"          # Direct hardcoded value
    CONFIGURATION_VALUE = "configuration_value"        # From config files/properties
    ENVIRONMENT_VARIABLE = "environment_variable"      # From env vars (good practice)
    BUILD_TIME_INJECTION = "build_time_injection"      # Injected at build time
    RUNTIME_RETRIEVAL = "runtime_retrieval"           # Retrieved at runtime (best practice)
    TEST_VALUE = "test_value"                          # Test/mock values
    ENCRYPTED_STORAGE = "encrypted_storage"            # Encrypted storage (good practice)
    UNKNOWN = "unknown"                                # Cannot determine usage pattern

class RiskLevel(Enum):
    """Risk levels based on contextual analysis"""
    MINIMAL = "minimal"      # Likely false positive or test value
    LOW = "low"             # Low risk based on context
    MODERATE = "moderate"   # Moderate risk requiring attention
    HIGH = "high"           # High risk requiring prompt action
    CRITICAL = "critical"   # Critical risk requiring immediate action

@dataclass
class UsageContext:
    """
    Represents the context in which a detected secret is used within the application.
    
    This class captures information about how a secret is embedded, accessed, and
    utilized within the codebase to help determine its actual security impact.
    """
    usage_type: SecretUsageType = SecretUsageType.UNKNOWN
    is_encrypted: bool = False
    is_obfuscated: bool = False
    has_validation: bool = False
    access_pattern: str = ""
    surrounding_variables: List[str] = field(default_factory=list)
    method_context: Optional[str] = None
    class_context: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'usage_type': self.usage_type.value,
            'is_encrypted': self.is_encrypted,
            'is_obfuscated': self.is_obfuscated, 
            'has_validation': self.has_validation,
            'access_pattern': self.access_pattern,
            'surrounding_variables': self.surrounding_variables,
            'method_context': self.method_context,
            'class_context': self.class_context
        }

@dataclass
class ContextMetadata:
    """
    Metadata about the contextual analysis performed on a security finding.
    
    This class contains information about the analysis process, confidence levels,
    and correlation with other findings or analysis modules.
    """
    analysis_confidence: ContextConfidence = ContextConfidence.MEDIUM
    false_positive_probability: float = 0.5  # 0.0 = definitely real, 1.0 = definitely false positive
    risk_correlation_score: float = 0.0      # Correlation with other risk indicators
    behavior_correlation: List[str] = field(default_factory=list)  # Related behavior analysis findings
    api_correlation: List[str] = field(default_factory=list)       # Related API usage findings
    context_analysis_version: str = "1.0"    # Version of context analysis used
    analysis_timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'analysis_confidence': self.analysis_confidence.value,
            'false_positive_probability': self.false_positive_probability,
            'risk_correlation_score': self.risk_correlation_score,
            'behavior_correlation': self.behavior_correlation,
            'api_correlation': self.api_correlation,
            'context_analysis_version': self.context_analysis_version,
            'analysis_timestamp': self.analysis_timestamp
        }

@dataclass
class ContextualFinding:
    """
    Enhanced security finding that includes contextual analysis information.
    
    This class extends traditional security findings with contextual intelligence,
    usage pattern analysis, and correlation with other analysis results to provide
    more accurate and actionable security insights.
    
    Attributes:
        original_finding: The original detection result from pattern matching
        usage_context: Information about how the secret is used in code
        context_metadata: Metadata about the contextual analysis performed
        adjusted_severity: Severity level adjusted based on contextual analysis
        adjusted_risk_level: Risk level based on contextual factors
        contextual_evidence: Additional evidence from contextual analysis
        remediation_priority: Priority for remediation based on context
        false_positive_indicators: List of factors suggesting false positive
    """
    original_finding: Dict[str, Any]
    usage_context: UsageContext = field(default_factory=UsageContext)
    context_metadata: ContextMetadata = field(default_factory=ContextMetadata)
    adjusted_severity: Optional[str] = None
    adjusted_risk_level: RiskLevel = RiskLevel.MODERATE
    contextual_evidence: List[str] = field(default_factory=list)
    remediation_priority: int = 5  # 1-10 scale, 10 = highest priority
    false_positive_indicators: List[str] = field(default_factory=list)
    
    @property
    def is_likely_false_positive(self) -> bool:
        """Determine if this finding is likely a false positive based on context"""
        return self.context_metadata.false_positive_probability > 0.7
    
    @property
    def requires_immediate_attention(self) -> bool:
        """Determine if this finding requires immediate attention"""
        return (self.adjusted_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] and 
                not self.is_likely_false_positive)
    
    def get_contextual_description(self) -> str:
        """Generate a contextual description of the finding"""
        base_type = self.original_finding.get('type', 'Unknown Secret')
        usage = self.usage_context.usage_type.value.replace('_', ' ').title()
        
        if self.is_likely_false_positive:
            return f"{base_type} (Likely False Positive - {usage})"
        elif self.adjusted_risk_level == RiskLevel.CRITICAL:
            return f"{base_type} (Critical Risk - {usage})"
        else:
            return f"{base_type} ({usage})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation for JSON serialization"""
        return {
            'original_finding': self.original_finding,
            'usage_context': self.usage_context.to_dict(),
            'context_metadata': self.context_metadata.to_dict(),
            'adjusted_severity': self.adjusted_severity,
            'adjusted_risk_level': self.adjusted_risk_level.value,
            'contextual_evidence': self.contextual_evidence,
            'remediation_priority': self.remediation_priority,
            'false_positive_indicators': self.false_positive_indicators,
            'is_likely_false_positive': self.is_likely_false_positive,
            'requires_immediate_attention': self.requires_immediate_attention,
            'contextual_description': self.get_contextual_description()
        }
    
    @classmethod
    def from_original_finding(cls, original_finding: Dict[str, Any]) -> 'ContextualFinding':
        """Create a ContextualFinding from an original detection result"""
        return cls(original_finding=original_finding)