#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Coordinator

Coordinator class for orchestrating all detection engines and aggregating results.
Follows Single Responsibility Principle by focusing only on coordination.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
import logging
from typing import List, Dict, Any
from ....core.base_classes import AnalysisContext, AnalysisStatus
from ....results.LibraryDetectionResults import DetectedLibrary
from .heuristic_engine import HeuristicDetectionEngine
from .similarity_engine import SimilarityDetectionEngine
from .native_engine import NativeLibraryDetectionEngine
from .androidx_engine import AndroidXDetectionEngine
from .apktool_detection_engine import ApktoolDetectionEngine

# Import result class - need to handle circular import
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .. import LibraryDetectionResult


class LibraryDetectionCoordinator:
    """
    Coordinator class for orchestrating all detection engines.
    
    Single Responsibility: Coordinate detection engines and aggregate results.
    """
    
    def __init__(self, parent_module):
        self.parent = parent_module
        self.logger = parent_module.logger
        
        # Initialize detection engines
        self.heuristic_engine = HeuristicDetectionEngine(parent_module)
        self.similarity_engine = SimilarityDetectionEngine(parent_module)
        self.native_engine = NativeLibraryDetectionEngine(parent_module)
        self.androidx_engine = AndroidXDetectionEngine(parent_module)
        self.apktool_engine = ApktoolDetectionEngine(parent_module.config, parent_module.logger)
        
    def execute_full_analysis(self, apk_path: str, context: AnalysisContext) -> 'LibraryDetectionResult':
        """
        Execute complete library detection analysis using all engines.
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            LibraryDetectionResult with comprehensive detection results
        """
        # Import here to avoid circular import
        from .. import LibraryDetectionResult
        
        start_time = time.time()
        self.logger.info(f"Starting comprehensive library detection for {apk_path}")
        
        try:
            detected_libraries = []
            stage1_libraries = []
            stage2_libraries = []
            analysis_errors = []
            stage_timings = {}
            
            # Stage 1: Heuristic Detection
            if self.parent.enable_stage1:
                heuristic_result = self.heuristic_engine.execute_detection(context, analysis_errors)
                stage1_libraries = heuristic_result['libraries']
                detected_libraries.extend(stage1_libraries)
                stage_timings['stage1_time'] = heuristic_result['execution_time']
            else:
                stage_timings['stage1_time'] = 0.0
                
            # Stage 2: Similarity Detection
            if self.parent.enable_stage2:
                similarity_result = self.similarity_engine.execute_detection(context, analysis_errors, detected_libraries)
                stage2_libraries = similarity_result['libraries']
                detected_libraries.extend(stage2_libraries)
                stage_timings['stage2_time'] = similarity_result['execution_time']
            else:
                stage_timings['stage2_time'] = 0.0
                
            # Stage 3: Native Library Detection
            native_result = self.native_engine.execute_detection(context, analysis_errors)
            native_libraries = native_result['libraries']
            detected_libraries.extend(native_libraries)
            stage_timings['stage3_time'] = native_result['execution_time']
            
            # Stage 4: AndroidX Detection
            androidx_result = self.androidx_engine.execute_detection(context, analysis_errors)
            androidx_libraries = androidx_result['libraries']
            detected_libraries.extend(androidx_libraries)
            stage_timings['stage4_time'] = androidx_result['execution_time']
            
            # Stage 5: Apktool-based Detection (requires apktool extraction)
            if self.apktool_engine.is_available(context):
                self.logger.info("Apktool results available, running apktool-based detection")
                try:
                    apktool_libraries = self.apktool_engine.detect_libraries(context, analysis_errors)
                    detected_libraries.extend(apktool_libraries)
                    self.logger.info(f"Apktool detection found {len(apktool_libraries)} libraries")
                except Exception as e:
                    error_msg = f"Apktool detection engine failed: {str(e)}"
                    self.logger.error(error_msg)
                    analysis_errors.append(error_msg)
            else:
                self.logger.debug("Apktool results not available, skipping apktool-based detection")
            
            # Remove duplicates
            detected_libraries = self.parent._deduplicate_libraries(detected_libraries)
            
            execution_time = time.time() - start_time
            
            self.logger.info(f"Library detection completed: {len(detected_libraries)} unique libraries detected")
            self.logger.info(f"Total execution time: {execution_time:.2f}s (Stage 1: {stage_timings['stage1_time']:.2f}s, Stage 2: {stage_timings['stage2_time']:.2f}s, Stage 3: {stage_timings['stage3_time']:.2f}s, Stage 4: {stage_timings['stage4_time']:.2f}s)")
            
            return LibraryDetectionResult(
                module_name=self.parent.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                detected_libraries=detected_libraries,
                heuristic_libraries=stage1_libraries,
                similarity_libraries=stage2_libraries,
                analysis_errors=analysis_errors,
                stage1_time=stage_timings['stage1_time'],
                stage2_time=stage_timings['stage2_time']
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Library detection analysis failed: {str(e)}"
            self.logger.error(error_msg)
            
            # Import here to avoid circular import
            from .. import LibraryDetectionResult
            
            return LibraryDetectionResult(
                module_name=self.parent.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=error_msg,
                analysis_errors=[error_msg]
            )