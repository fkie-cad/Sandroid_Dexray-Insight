#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Native Library Detection Engine for Library Detection

Specialized engine for native library detection (.so files).
Handles timing, error management, and result processing for native library detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import List, Dict, Any
from dexray_insight.core.base_classes import AnalysisContext


class NativeLibraryDetectionEngine:
    """
    Specialized engine for native library detection.
    
    Single Responsibility: Handle native (.so) library detection with timing and error management.
    """
    
    def __init__(self, parent_module):
        self.parent = parent_module
        self.logger = parent_module.logger
        
    def execute_detection(self, context: AnalysisContext, analysis_errors: List[str]) -> Dict[str, Any]:
        """
        Execute native library detection with comprehensive timing and error handling.
        
        Args:
            context: Analysis context with existing results
            analysis_errors: List to append any analysis errors
            
        Returns:
            Dict with 'libraries', 'execution_time', and 'success' keys
        """
        start_time = time.time()
        
        try:
            self.logger.debug("Starting Stage 3: Native library detection")
            detected_libraries = self.parent._detect_native_libraries(context)
            execution_time = time.time() - start_time
            
            self.logger.info(f"Stage 3 detected {len(detected_libraries)} native libraries")
            
            return {
                'libraries': detected_libraries,
                'execution_time': execution_time,
                'success': True
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Native library detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)
            
            return {
                'libraries': [],
                'execution_time': execution_time,
                'success': False
            }