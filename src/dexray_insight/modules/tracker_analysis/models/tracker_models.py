#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Analysis Data Models

Data models for representing detected trackers and analysis results.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class DetectedTracker:
    """Container for a detected tracker with metadata"""
    name: str
    version: Optional[str] = None
    description: str = ""
    category: str = ""
    website: str = ""
    code_signature: str = ""
    network_signature: str = ""
    detection_method: str = ""
    locations: List[str] = None
    confidence: float = 1.0
    
    def __post_init__(self):
        if self.locations is None:
            self.locations = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'category': self.category,
            'website': self.website,
            'code_signature': self.code_signature,
            'network_signature': self.network_signature,
            'detection_method': self.detection_method,
            'locations': self.locations,
            'confidence': self.confidence
        }