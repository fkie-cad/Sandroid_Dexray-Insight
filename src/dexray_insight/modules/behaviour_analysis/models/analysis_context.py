#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Behavior Analysis Context

Extended context for behavior analysis with mode-specific
data and analysis coordination information.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .behavior_evidence import BehaviorEvidence


@dataclass
class BehaviorAnalysisContext:
    """Extended context for behavior analysis operations"""
    
    # Analysis mode configuration
    analysis_mode: str  # 'fast' or 'deep'
    deep_mode_enabled: bool = False
    
    # Androguard objects for analysis
    apk_obj: Optional[Any] = None
    dex_obj: Optional[Any] = None
    dx_obj: Optional[Any] = None
    
    # Analysis state tracking
    analyzed_behaviors: List[str] = None
    total_evidence_found: int = 0
    analysis_start_time: Optional[float] = None
    
    # Configuration and settings
    config: Optional[Dict[str, Any]] = None
    analyzer_settings: Optional[Dict[str, Any]] = None
    
    # Results aggregation
    evidence_by_type: Optional[Dict[str, List[BehaviorEvidence]]] = None
    high_confidence_evidence: Optional[List[BehaviorEvidence]] = None
    
    def __post_init__(self):
        if self.analyzed_behaviors is None:
            self.analyzed_behaviors = []
        if self.evidence_by_type is None:
            self.evidence_by_type = {}
        if self.high_confidence_evidence is None:
            self.high_confidence_evidence = []
    
    def add_evidence(self, behavior_type: str, evidence: List[BehaviorEvidence]) -> None:
        """Add evidence for a specific behavior type"""
        if behavior_type not in self.evidence_by_type:
            self.evidence_by_type[behavior_type] = []
        
        self.evidence_by_type[behavior_type].extend(evidence)
        self.total_evidence_found += len(evidence)
        
        # Track high confidence evidence
        for ev in evidence:
            if ev.is_high_confidence():
                self.high_confidence_evidence.append(ev)
    
    def mark_behavior_analyzed(self, behavior_type: str) -> None:
        """Mark a behavior type as analyzed"""
        if behavior_type not in self.analyzed_behaviors:
            self.analyzed_behaviors.append(behavior_type)
    
    def get_evidence_summary(self) -> Dict[str, int]:
        """Get summary of evidence by type"""
        summary = {}
        for behavior_type, evidence_list in self.evidence_by_type.items():
            summary[behavior_type] = len(evidence_list)
        return summary
    
    def get_high_confidence_count(self) -> int:
        """Get count of high confidence evidence"""
        return len(self.high_confidence_evidence)
    
    def is_deep_mode(self) -> bool:
        """Check if running in deep analysis mode"""
        return self.deep_mode_enabled and self.analysis_mode == 'deep'
    
    def has_dex_objects(self) -> bool:
        """Check if DEX objects are available for analysis"""
        return self.dex_obj is not None and self.dx_obj is not None
    
    def get_analyzed_behavior_count(self) -> int:
        """Get count of analyzed behavior types"""
        return len(self.analyzed_behaviors)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for logging/debugging"""
        return {
            'analysis_mode': self.analysis_mode,
            'deep_mode_enabled': self.deep_mode_enabled,
            'analyzed_behaviors': self.analyzed_behaviors,
            'total_evidence_found': self.total_evidence_found,
            'high_confidence_count': self.get_high_confidence_count(),
            'has_dex_objects': self.has_dex_objects(),
            'evidence_summary': self.get_evidence_summary()
        }