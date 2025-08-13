#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Device Information Analyzer

Detects when applications attempt to access device-specific information
such as device model, Android ID, and hardware identifiers.
"""

import re
import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class DeviceAnalyzer:
    """Analyzer for device information access behaviors"""
    
    DEVICE_PATTERNS = [
        r'android\.os\.Build\.MODEL',
        r'Build\.MODEL',
        r'getSystemService.*DEVICE_POLICY_SERVICE',
        r'getModel\(\)',
        r'android\.provider\.Settings\.Secure\.ANDROID_ID'
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_device_model_access(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app accesses device model information"""
        evidence = []
        
        try:
            # Search in DEX strings
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        dex_strings = dex.get_strings()
                        for string in dex_strings:
                            string_val = str(string)
                            for pattern in self.DEVICE_PATTERNS:
                                if re.search(pattern, string_val, re.IGNORECASE):
                                    evidence.append(BehaviorEvidence(
                                        type='string',
                                        content=string_val,
                                        pattern_matched=pattern,
                                        location=f'DEX {i+1} strings',
                                        dex_index=i
                                    ))
                    except Exception as e:
                        self.logger.debug(f"Error analyzing device model access in DEX {i}: {e}")
            
            # Search in smali code
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        for cls in dex.get_classes():
                            class_source = cls.get_source()
                            if class_source:
                                for pattern in self.DEVICE_PATTERNS:
                                    matches = re.finditer(pattern, class_source, re.IGNORECASE)
                                    for match in matches:
                                        # Get line number context
                                        lines = class_source[:match.start()].count('\n')
                                        evidence.append(BehaviorEvidence(
                                            type='code',
                                            content=match.group(),
                                            pattern_matched=pattern,
                                            class_name=cls.get_name(),
                                            line_number=lines + 1,
                                            dex_index=i
                                        ))
                    except Exception as e:
                        self.logger.debug(f"Error analyzing device model access in smali DEX {i}: {e}")
            
            # Add finding to result
            result.add_finding(
                "device_model_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application attempts to access device model information"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Device model analysis failed: {e}")
            return []
    
    def analyze_android_version_access(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app accesses Android version information"""
        evidence = []
        patterns = [
            r'android\.os\.Build\.VERSION',
            r'Build\.VERSION',
            r'SDK_INT',
            r'RELEASE',
            r'getSystemProperty.*version'
        ]
        
        try:
            # Import here to avoid circular imports
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, patterns, "Android version access"
            )
            
            result.add_finding(
                "android_version_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application accesses Android version information"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Android version analysis failed: {e}")
            return []