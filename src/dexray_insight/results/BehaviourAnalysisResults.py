#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from ..core.base_classes import BaseResult

@dataclass
class BehaviourAnalysisFinding:
    """Represents a single behaviour analysis finding"""
    feature_name: str
    detected: bool
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'feature_name': self.feature_name,
            'detected': self.detected,
            'evidence': self.evidence,
            'description': self.description
        }

@dataclass
class BehaviourAnalysisResults(BaseResult):
    """Results class for behaviour analysis module"""
    findings: Dict[str, BehaviourAnalysisFinding] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)
    androguard_objects: Optional[Dict[str, Any]] = field(default=None, repr=False)
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'findings': {name: finding.to_dict() for name, finding in self.findings.items()},
            'summary': self.summary
            # Note: androguard_objects are not serialized as they contain binary objects
        })
        return base_dict
    
    def add_finding(self, feature_name: str, detected: bool, evidence: List[Dict[str, Any]] = None, description: str = ""):
        """Add a finding to the results"""
        if evidence is None:
            evidence = []
        self.findings[feature_name] = BehaviourAnalysisFinding(
            feature_name=feature_name,
            detected=detected,
            evidence=evidence,
            description=description
        )
    
    def get_detected_features(self) -> List[str]:
        """Get list of detected feature names"""
        return [name for name, finding in self.findings.items() if finding.detected]
    
    def get_terminal_summary(self) -> str:
        """Get brief summary for terminal output"""
        detected = self.get_detected_features()
        if not detected:
            return "🔍 Behaviour Analysis: No suspicious behaviors detected"
        
        summary_parts = []
        for feature in detected:
            summary_parts.append(f"✓ {feature}")
        
        return f"🔍 Behaviour Analysis: {len(detected)} behaviors detected:\n" + "\n".join(f"  {part}" for part in summary_parts)