#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pattern Search Engine

Provides centralized pattern matching capabilities for behavior analysis.
Handles searching through DEX strings, smali code, and other APK components.
"""

import re
import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class PatternSearchEngine:
    """Centralized pattern search engine for behavior analysis"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def search_patterns_in_apk(self, apk_obj, dex_obj, dx_obj, patterns: List[str], 
                             feature_name: str) -> List[BehaviorEvidence]:
        """Helper method to search patterns in APK strings and code"""
        evidence = []
        
        try:
            # Search in DEX strings
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        dex_strings = dex.get_strings()
                        for string in dex_strings:
                            string_val = str(string)
                            for pattern in patterns:
                                if re.search(pattern, string_val, re.IGNORECASE):
                                    evidence.append(BehaviorEvidence(
                                        type='string',
                                        content=string_val,
                                        pattern_matched=pattern,
                                        location=f'DEX {i+1} strings',
                                        dex_index=i
                                    ))
                    except Exception as e:
                        self.logger.debug(f"Error analyzing {feature_name} in DEX strings {i}: {e}")
            
            # Search in smali code
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        for cls in dex.get_classes():
                            class_source = cls.get_source()
                            if class_source:
                                for pattern in patterns:
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
                        self.logger.debug(f"Error analyzing {feature_name} in smali DEX {i}: {e}")
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Pattern search failed for {feature_name}: {e}")
            return []
    
    def search_in_strings(self, dex_obj, patterns: List[str], feature_name: str) -> List[BehaviorEvidence]:
        """Search patterns only in DEX strings"""
        evidence = []
        
        if not dex_obj:
            return evidence
        
        try:
            for i, dex in enumerate(dex_obj):
                try:
                    dex_strings = dex.get_strings()
                    for string in dex_strings:
                        string_val = str(string)
                        for pattern in patterns:
                            if re.search(pattern, string_val, re.IGNORECASE):
                                evidence.append(BehaviorEvidence(
                                    type='string',
                                    content=string_val,
                                    pattern_matched=pattern,
                                    location=f'DEX {i+1} strings',
                                    dex_index=i
                                ))
                except Exception as e:
                    self.logger.debug(f"Error searching strings in DEX {i} for {feature_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"String search failed for {feature_name}: {e}")
        
        return evidence
    
    def search_in_code(self, dex_obj, patterns: List[str], feature_name: str) -> List[BehaviorEvidence]:
        """Search patterns only in smali code"""
        evidence = []
        
        if not dex_obj:
            return evidence
        
        try:
            for i, dex in enumerate(dex_obj):
                try:
                    for cls in dex.get_classes():
                        class_source = cls.get_source()
                        if class_source:
                            for pattern in patterns:
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
                    self.logger.debug(f"Error searching code in DEX {i} for {feature_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"Code search failed for {feature_name}: {e}")
        
        return evidence
    
    def check_permissions(self, apk_obj, permission_list: List[str]) -> List[BehaviorEvidence]:
        """Check for specific permissions in the APK"""
        evidence = []
        
        try:
            permissions = apk_obj.get_permissions()
            for permission in permission_list:
                if permission in permissions:
                    evidence.append(BehaviorEvidence(
                        type='permission',
                        content=permission,
                        location='AndroidManifest.xml'
                    ))
        except Exception as e:
            self.logger.error(f"Permission check failed: {e}")
        
        return evidence