#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Similarity Detection Engine for Library Detection

Specialized engine for similarity-based library detection using LibScan-style analysis.
Handles timing, error management, and result processing for similarity detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import List, Dict, Any
from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.results.LibraryDetectionResults import DetectedLibrary


class SimilarityDetectionEngine:
    """
    Specialized engine for similarity-based library detection.
    
    Single Responsibility: Handle LibScan-style similarity detection with timing and error management.
    """
    
    def __init__(self, parent_module):
        self.parent = parent_module
        self.logger = parent_module.logger
        
    def execute_detection(self, context: AnalysisContext, analysis_errors: List[str], 
                         existing_libraries: List[DetectedLibrary]) -> Dict[str, Any]:
        """
        Execute similarity detection with comprehensive timing and error handling.
        
        Args:
            context: Analysis context with existing results
            analysis_errors: List to append any analysis errors
            existing_libraries: Already detected libraries to avoid duplicates
            
        Returns:
            Dict with 'libraries', 'execution_time', and 'success' keys
        """
        start_time = time.time()
        
        try:
            self.logger.debug("Starting Stage 2: Similarity-based detection")
            detected_libraries = self.parent._perform_similarity_detection(context, analysis_errors, existing_libraries)
            execution_time = time.time() - start_time
            
            self.logger.info(f"Stage 2 detected {len(detected_libraries)} additional libraries using similarity analysis")
            
            return {
                'libraries': detected_libraries,
                'execution_time': execution_time,
                'success': True
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Similarity detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)
            
            return {
                'libraries': [],
                'execution_time': execution_time,
                'success': False
            }