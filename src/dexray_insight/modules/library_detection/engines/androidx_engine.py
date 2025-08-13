#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AndroidX Detection Engine for Library Detection

Specialized engine for AndroidX library detection.
Handles timing, error management, and result processing for AndroidX detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import List, Dict, Any
from ....core.base_classes import AnalysisContext


class AndroidXDetectionEngine:
    """
    Specialized engine for AndroidX library detection.
    
    Single Responsibility: Handle AndroidX library detection with timing and error management.
    """
    
    def __init__(self, parent_module):
        self.parent = parent_module
        self.logger = parent_module.logger
        
    def execute_detection(self, context: AnalysisContext, analysis_errors: List[str]) -> Dict[str, Any]:
        """
        Execute AndroidX library detection with comprehensive timing and error handling.
        
        Args:
            context: Analysis context with existing results
            analysis_errors: List to append any analysis errors
            
        Returns:
            Dict with 'libraries', 'execution_time', and 'success' keys
        """
        start_time = time.time()
        
        try:
            self.logger.debug("Starting Stage 4: AndroidX library detection")
            detected_libraries = self.parent._detect_androidx_libraries(context)
            execution_time = time.time() - start_time
            
            self.logger.info(f"Stage 4 detected {len(detected_libraries)} AndroidX libraries")
            
            return {
                'libraries': detected_libraries,
                'execution_time': execution_time,
                'success': True
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"AndroidX library detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)
            
            return {
                'libraries': [],
                'execution_time': execution_time,
                'success': False
            }