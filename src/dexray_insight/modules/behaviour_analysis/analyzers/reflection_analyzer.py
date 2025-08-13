#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reflection Analyzer

Detects when applications use Java reflection, which can be used
to bypass security restrictions or obfuscate functionality.
"""

import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class ReflectionAnalyzer:
    """Analyzer for Java reflection usage"""
    
    REFLECTION_PATTERNS = [
        r'Class\.forName\(',
        r'getDeclaredMethod\(',
        r'getMethod\(',
        r'invoke\(',
        r'java\.lang\.reflect',
        r'Method\.invoke\(',
        r'getDeclaredField\(',
        r'getField\('
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_reflection_usage(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app uses reflection"""
        try:
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.REFLECTION_PATTERNS, "reflection usage"
            )
            
            result.add_finding(
                "reflection_usage",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application uses Java reflection"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Reflection analysis failed: {e}")
            return []