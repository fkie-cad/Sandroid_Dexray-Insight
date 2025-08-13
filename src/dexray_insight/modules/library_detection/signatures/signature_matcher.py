#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Signature Matching for Library Detection

Contains functionality to match extracted signatures against known
library patterns for similarity-based detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import logging
from typing import List, Dict, Any
from ....results.LibraryDetectionResults import DetectedLibrary, LibraryDetectionMethod, LibraryCategory


class SignatureMatcher:
    """
    Matches extracted signatures against known library patterns.
    
    Single Responsibility: Handle signature comparison and similarity calculation
    for library detection.
    """
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.logger = logging.getLogger(__name__)
        self.similarity_threshold = similarity_threshold
    
    def match_class_signatures(self, signatures: Dict[str, Any], 
                              existing_libraries: List[DetectedLibrary]) -> List[DetectedLibrary]:
        """
        Match class signatures against known library patterns
        
        This is a simplified implementation. A full LibScan approach would
        require a comprehensive database of library signatures.
        
        Args:
            signatures: Extracted class signatures
            existing_libraries: Already detected libraries
            
        Returns:
            List of libraries detected via similarity
        """
        detected_libraries = []
        existing_names = {lib.name for lib in existing_libraries}
        
        # Simplified similarity detection based on method patterns
        # This would be much more sophisticated in a full implementation
        
        try:
            # Look for specific method patterns that indicate library usage
            library_indicators = {
                'Dagger': ['inject', 'provides', 'component'],
                'RxJava': ['subscribe', 'observable', 'scheduler'],
                'Timber': ['plant', 'tree', 'log'],
                'LeakCanary': ['install', 'watchActivity', 'heap'],
                'EventBus': ['register', 'unregister', 'post', 'subscribe']
            }
            
            for lib_name, indicators in library_indicators.items():
                if lib_name in existing_names:
                    continue
                
                matches = 0
                total_methods = 0
                
                for class_name, class_info in signatures.items():
                    for method_info in class_info.get('methods', []):
                        total_methods += 1
                        method_name = method_info.get('name', '').lower()
                        
                        for indicator in indicators:
                            if indicator in method_name:
                                matches += 1
                                break
                
                if total_methods > 0:
                    confidence = matches / min(total_methods, 100)  # Cap to avoid false positives
                    if confidence > 0.1:  # Minimum threshold for similarity detection
                        detected_library = DetectedLibrary(
                            name=lib_name,
                            detection_method=LibraryDetectionMethod.SIMILARITY,
                            category=LibraryCategory.UTILITY,  # Default category
                            confidence=confidence,
                            evidence=[f"Method pattern matches: {matches}/{total_methods}"]
                        )
                        detected_libraries.append(detected_library)
                        self.logger.debug(f"Detected {lib_name} via similarity (confidence: {confidence:.2f})")
                        
        except Exception as e:
            self.logger.error(f"Error in signature matching: {str(e)}")
        
        return detected_libraries
    
    def calculate_library_similarity(self, lib_name: str, signatures: Dict[str, Any],
                                   lib_methods: Dict[str, List[str]], 
                                   lib_call_chains: Dict[str, List[str]],
                                   lib_classes: Dict[str, Dict[str, Any]]) -> float:
        """
        Calculate similarity between extracted signatures and a known library
        
        Args:
            lib_name: Name of the library to compare against
            signatures: Extracted application signatures
            lib_methods: Known library method patterns
            lib_call_chains: Known library call chain patterns
            lib_classes: Known library class structures
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            # Extract method patterns from app signatures
            app_methods = {}
            app_call_chains = {}
            app_classes = {}
            
            for class_name, class_info in signatures.items():
                app_classes[class_name] = {
                    'methods': len(class_info.get('methods', [])),
                    'fields': 0  # Would need to extract this from DEX analysis
                }
                
                for method_info in class_info.get('methods', []):
                    method_key = f"{class_name}.{method_info.get('name', '')}"
                    app_methods[method_key] = method_info.get('opcodes', [])
            
            # Calculate similarity scores
            method_similarity = self._calculate_method_similarity(lib_methods, app_methods)
            call_chain_similarity = self._calculate_call_chain_similarity(lib_call_chains, app_call_chains)
            structural_similarity = self._calculate_structural_similarity(lib_classes, app_classes)
            
            # Weighted average
            overall_similarity = (
                method_similarity * 0.5 +
                call_chain_similarity * 0.3 +
                structural_similarity * 0.2
            )
            
            return overall_similarity
            
        except Exception as e:
            self.logger.error(f"Error calculating similarity for {lib_name}: {str(e)}")
            return 0.0
    
    def _calculate_method_similarity(self, lib_methods: Dict[str, List[str]], 
                                   app_methods: Dict[str, List[str]]) -> float:
        """Calculate similarity based on method opcode patterns"""
        if not lib_methods or not app_methods:
            return 0.0
        
        matches = 0
        total_lib_methods = len(lib_methods)
        
        for lib_method, lib_opcodes in lib_methods.items():
            best_match = 0.0
            
            for app_method, app_opcodes in app_methods.items():
                if not lib_opcodes or not app_opcodes:
                    continue
                
                # Simple sequence matching
                common_opcodes = len(set(lib_opcodes) & set(app_opcodes))
                total_opcodes = len(set(lib_opcodes) | set(app_opcodes))
                
                if total_opcodes > 0:
                    similarity = common_opcodes / total_opcodes
                    best_match = max(best_match, similarity)
            
            if best_match >= 0.6:  # Threshold for method similarity
                matches += 1
        
        return matches / total_lib_methods if total_lib_methods > 0 else 0.0
    
    def _calculate_call_chain_similarity(self, lib_chains: Dict[str, List[str]], 
                                       app_chains: Dict[str, List[str]]) -> float:
        """Calculate similarity based on call chain patterns"""
        if not lib_chains or not app_chains:
            return 0.0
        
        matches = 0
        total_lib_chains = len(lib_chains)
        
        for lib_method, lib_chain in lib_chains.items():
            for app_method, app_chain in app_chains.items():
                # Look for common call patterns
                common_calls = len(set(lib_chain) & set(app_chain))
                if common_calls > 0 and len(lib_chain) > 0:
                    chain_similarity = common_calls / len(lib_chain)
                    if chain_similarity >= 0.5:  # Threshold for call chain similarity
                        matches += 1
                        break
        
        return matches / total_lib_chains if total_lib_chains > 0 else 0.0
    
    def _calculate_structural_similarity(self, lib_classes: Dict[str, Dict[str, Any]], 
                                       app_classes: Dict[str, Dict[str, Any]]) -> float:
        """Calculate structural similarity based on class relationships"""
        if not lib_classes or not app_classes:
            return 0.0
        
        matches = 0
        total_lib_classes = len(lib_classes)
        
        for lib_class, lib_info in lib_classes.items():
            best_match = 0.0
            
            for app_class, app_info in app_classes.items():
                similarity = self._compare_class_structure(lib_info, app_info)
                best_match = max(best_match, similarity)
            
            if best_match >= 0.6:  # Threshold for structural similarity
                matches += 1
        
        return matches / total_lib_classes if total_lib_classes > 0 else 0.0
    
    def _compare_class_structure(self, lib_class: Dict[str, Any], app_class: Dict[str, Any]) -> float:
        """Compare two class structures for similarity"""
        score = 0.0
        comparisons = 0
        
        # Compare method count similarity
        lib_methods = lib_class.get('methods', [])
        app_methods = app_class.get('methods', [])
        
        # Handle both integer counts and list formats
        lib_method_count = lib_methods if isinstance(lib_methods, int) else len(lib_methods)
        app_method_count = app_methods if isinstance(app_methods, int) else len(app_methods)
        
        if lib_method_count > 0 and app_method_count > 0:
            method_ratio = min(lib_method_count, app_method_count) / max(lib_method_count, app_method_count)
            score += method_ratio
            comparisons += 1
        
        # Compare field count similarity
        lib_fields = lib_class.get('fields', [])
        app_fields = app_class.get('fields', [])
        
        # Handle both integer counts and list formats
        lib_field_count = lib_fields if isinstance(lib_fields, int) else len(lib_fields)
        app_field_count = app_fields if isinstance(app_fields, int) else len(app_fields)
        
        if lib_field_count > 0 and app_field_count > 0:
            field_ratio = min(lib_field_count, app_field_count) / max(lib_field_count, app_field_count)
            score += field_ratio
            comparisons += 1
        
        return score / comparisons if comparisons > 0 else 0.0