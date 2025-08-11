#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Analysis Module - Refactored Main Module

Advertising and analytics tracker detection module using specialized detectors.
Refactored to use submodules following Single Responsibility Principle.

Phase 7 TDD Refactoring: Main module now delegates to specialized detectors
and imports databases from dedicated submodules.
"""

import time
import logging
from typing import List, Dict, Any, Set
from dataclasses import dataclass

from dexray_insight.core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module

# Import from submodules
from .models import DetectedTracker
from .databases import TrackerDatabase, ExodusAPIClient
from .detectors import PatternDetector, VersionExtractor, TrackerDeduplicator


@dataclass
class TrackerAnalysisResult(BaseResult):
    """Result class for tracker analysis"""
    detected_trackers: List[DetectedTracker] = None
    total_trackers: int = 0
    exodus_trackers: List[Dict[str, Any]] = None
    custom_detections: List[DetectedTracker] = None
    analysis_errors: List[str] = None
    
    def __post_init__(self):
        if self.detected_trackers is None:
            self.detected_trackers = []
        if self.custom_detections is None:
            self.custom_detections = []
        if self.analysis_errors is None:
            self.analysis_errors = []
        self.total_trackers = len(self.detected_trackers)
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'detected_trackers': [tracker.to_dict() for tracker in self.detected_trackers],
            'total_trackers': self.total_trackers,
            'custom_detections': [tracker.to_dict() for tracker in self.custom_detections],
            'analysis_errors': self.analysis_errors
        })
        return base_dict


@register_module('tracker_analysis')
class TrackerAnalysisModule(BaseAnalysisModule):
    """
    Advertising and analytics tracker detection module.
    
    Phase 7 TDD Refactoring: Refactored to use specialized detectors and
    databases from dedicated submodules following SRP.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Initialize specialized components
        self.tracker_database = TrackerDatabase()
        self.exodus_client = ExodusAPIClient(config)
        self.pattern_detector = PatternDetector()
        self.version_extractor = VersionExtractor()
        self.deduplicator = TrackerDeduplicator()
        
        # Configuration
        self.fetch_exodus_trackers = config.get('fetch_exodus_trackers', True)
    
    def get_dependencies(self) -> List[str]:
        """Dependencies: string analysis for pattern matching"""
        return ['string_analysis']
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> TrackerAnalysisResult:
        """
        Perform tracker detection analysis using specialized detectors.
        
        Refactored coordinator function that delegates to specialized detection components
        following the Single Responsibility Principle. Each detection concern is handled
        by a dedicated detector with its own logic and error management.
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            TrackerAnalysisResult with comprehensive detection results
        """
        start_time = time.time()
        
        self.logger.info(f"Starting tracker analysis for {apk_path}")
        
        try:
            detected_trackers = []
            analysis_errors = []
            exodus_trackers = []
            custom_detections = []
            
            # Extract strings from analysis context
            all_strings = self._extract_strings_from_context(context, analysis_errors)
            
            self.logger.debug(f"Analyzing {len(all_strings)} strings for tracker patterns")
            
            # Phase 1: Fetch Exodus Privacy trackers if enabled
            if self.fetch_exodus_trackers and self.exodus_client.is_enabled():
                try:
                    exodus_trackers = self.exodus_client.fetch_trackers()
                    self.logger.debug(f"Loaded {len(exodus_trackers)} trackers from Exodus Privacy")
                except Exception as e:
                    error_msg = f"Failed to fetch Exodus Privacy trackers: {str(e)}"
                    self.logger.warning(error_msg)
                    analysis_errors.append(error_msg)
            
            # Phase 2: Detect trackers using built-in database
            custom_detections = self._detect_custom_trackers(all_strings, context)
            detected_trackers.extend(custom_detections)
            
            # Phase 3: Detect trackers using Exodus Privacy patterns
            if exodus_trackers:
                exodus_detections = self._detect_exodus_trackers(all_strings, exodus_trackers, context)
                detected_trackers.extend(exodus_detections)
            
            # Phase 4: Remove duplicates and finalize results
            unique_trackers = self.deduplicator.deduplicate_trackers(detected_trackers)
            
            execution_time = time.time() - start_time
            
            # Log summary
            self._log_detection_summary(unique_trackers)
            
            return TrackerAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                detected_trackers=unique_trackers,
                total_trackers=len(unique_trackers),
                custom_detections=custom_detections,
                analysis_errors=analysis_errors
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Tracker analysis failed: {str(e)}")
            
            return TrackerAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                total_trackers=0,
                analysis_errors=[str(e)]
            )
    
    def _extract_strings_from_context(self, context: AnalysisContext, analysis_errors: List[str]) -> Set[str]:
        """
        Extract all available strings from the analysis context.
        
        Args:
            context: Analysis context with string analysis results
            analysis_errors: List to append any errors to
            
        Returns:
            Set of all strings for pattern matching
        """
        all_strings = set()
        
        # Get strings from string analysis module
        string_analysis = context.get_result('string_analysis')
        if not string_analysis:
            self.logger.warning("String analysis results not available, limited tracker detection")
            return all_strings
        
        # Collect strings from different categories
        if hasattr(string_analysis, 'urls') and string_analysis.urls:
            all_strings.update(string_analysis.urls)
        if hasattr(string_analysis, 'domains') and string_analysis.domains:
            all_strings.update(string_analysis.domains)
        if hasattr(string_analysis, 'emails') and string_analysis.emails:
            all_strings.update(string_analysis.emails)
        
        # Extract raw strings from androguard if available
        string_locations = {}
        if context.androguard_obj:
            try:
                dex_obj = context.androguard_obj.get_androguard_dex()
                if dex_obj:
                    for dex in dex_obj:
                        # Extract strings with class/method context
                        for class_analysis in dex.get_classes():
                            class_name = class_analysis.get_name()
                            for method in class_analysis.get_methods():
                                method_name = method.get_name()
                                method_full_name = f"{class_name}->{method_name}"
                                
                                # Get strings from method bytecode
                                try:
                                    for instruction in method.get_instructions():
                                        if hasattr(instruction, 'get_operands'):
                                            for operand in instruction.get_operands():
                                                if hasattr(operand, 'get_value'):
                                                    operand_value = operand.get_value()
                                                    if isinstance(operand_value, str) and len(operand_value) > 3:
                                                        all_strings.add(operand_value)
                                                        if operand_value not in string_locations:
                                                            string_locations[operand_value] = []
                                                        string_locations[operand_value].append(method_full_name)
                                except Exception:
                                    pass  # Skip errors in instruction parsing
                        
                        # Also get all strings from DEX (fallback)
                        for string in dex.get_strings():
                            string_value = str(string)
                            all_strings.add(string_value)
                            # If no specific location found, mark as generic
                            if string_value not in string_locations:
                                string_locations[string_value] = ["DEX strings pool"]
            except Exception as e:
                self.logger.warning(f"Error extracting raw strings: {str(e)}")
                # Fallback to simple string extraction
                try:
                    dex_obj = context.androguard_obj.get_androguard_dex()
                    if dex_obj:
                        for dex in dex_obj:
                            for string in dex.get_strings():
                                string_value = str(string)
                                all_strings.add(string_value)
                                string_locations[string_value] = ["DEX strings pool"]
                except Exception:
                    pass
        
        # Store string locations in context for use in pattern matching
        context.string_locations = string_locations
        
        return all_strings
    
    def _detect_custom_trackers(self, strings: Set[str], context: AnalysisContext) -> List[DetectedTracker]:
        """Detect trackers using built-in tracker database"""
        detected = []
        
        tracker_database = self.tracker_database.get_tracker_database()
        
        for tracker_name, tracker_info in tracker_database.items():
            detection_results = self.pattern_detector.detect_tracker_patterns(
                tracker_name, tracker_info, strings, context
            )
            if detection_results:
                detected.extend(detection_results)
        
        return detected
    
    def _detect_exodus_trackers(self, strings: Set[str], exodus_trackers: List[Dict[str, Any]], 
                              context: AnalysisContext) -> List[DetectedTracker]:
        """Detect trackers using Exodus Privacy patterns"""
        detected = []
        
        for tracker_info in exodus_trackers:
            detection_results = self.pattern_detector.detect_exodus_patterns(
                tracker_info, strings, context
            )
            if detection_results:
                detected.extend(detection_results)
        
        return detected
    
    def _log_detection_summary(self, trackers: List[DetectedTracker]):
        """Log a summary of detected trackers"""
        self.logger.info(f"Tracker analysis completed: {len(trackers)} trackers detected")
        
        for tracker in trackers:
            version_info = f" (v{tracker.version})" if tracker.version else ""
            self.logger.info(f"📍 {tracker.name}{version_info} - {tracker.category}")
        
        # Log category breakdown
        if trackers:
            categories = self.deduplicator.group_by_category(trackers)
            self.logger.debug(f"Trackers by category: {dict((k, len(v)) for k, v in categories.items())}")
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        # Validate Exodus client configuration
        if self.fetch_exodus_trackers and not self.exodus_client.is_enabled():
            self.logger.warning("Exodus tracker fetching enabled but client is disabled due to invalid configuration")
        
        return True