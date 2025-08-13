#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Heuristic Detection Engine for Library Detection

Specialized engine for heuristic-based library detection using known patterns.
Handles timing, error management, and result processing for heuristic detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import List, Dict, Any
from dexray_insight.core.base_classes import AnalysisContext


class HeuristicDetectionEngine:
    """
    Specialized engine for heuristic-based library detection.
    
    Single Responsibility: Handle heuristic detection with timing and error management.
    """
    
    def __init__(self, parent_module):
        self.parent = parent_module
        self.logger = parent_module.logger
        
    def execute_detection(self, context: AnalysisContext, analysis_errors: List[str]) -> Dict[str, Any]:
        """
        Execute heuristic detection with comprehensive timing and error handling.
        
        Args:
            context: Analysis context with existing results
            analysis_errors: List to append any analysis errors
            
        Returns:
            Dict with 'libraries', 'execution_time', and 'success' keys
        """
        start_time = time.time()
        
        try:
            self.logger.debug("Starting Stage 1: Heuristic-based detection")
            detected_libraries = self.parent._perform_heuristic_detection(context, analysis_errors)
            execution_time = time.time() - start_time
            
            self.logger.info(f"Stage 1 detected {len(detected_libraries)} libraries using heuristics")
            
            return {
                'libraries': detected_libraries,
                'execution_time': execution_time,
                'success': True
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Heuristic detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)
            
            return {
                'libraries': [],
                'execution_time': execution_time,
                'success': False
            }