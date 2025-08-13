#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Coordinator

Coordinator class for orchestrating all detection engines and aggregating results.
Follows Single Responsibility Principle by focusing only on coordination.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import List
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
            
            # Version analysis results will be shown in the main analysis summary instead
            # self._print_version_analysis_results(detected_libraries, context)
            
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
    
    def _print_version_analysis_results(self, libraries: List[DetectedLibrary], context):
        """
        Print enhanced version analysis results to console.
        Only displays when security analysis is enabled or version_analysis.security_analysis_only is False.
        
        Format: library name (version): smali path : years behind
        Example: Gson (2.8.5): /com/google/gson/ : 2.1 years behind
        """
        # Check if security analysis is enabled
        security_analysis_enabled = context.config.get('security', {}).get('enable_owasp_assessment', False)
        
        # Check version analysis configuration
        version_config = context.config.get('modules', {}).get('library_detection', {}).get('version_analysis', {})
        security_analysis_only = version_config.get('security_analysis_only', True)
        version_analysis_enabled = version_config.get('enabled', True)
        
        # Skip version analysis display if not enabled or security-only mode is active without security analysis
        if not version_analysis_enabled:
            self.logger.info("Version analysis disabled in configuration")
            return
            
        if security_analysis_only and not security_analysis_enabled:
            self.logger.info("Version analysis only runs during security analysis (use -s flag)")
            return
        
        libraries_with_versions = [lib for lib in libraries if lib.version]
        
        if not libraries_with_versions:
            self.logger.info("No libraries with version information found for version analysis display")
            return
        
        self.logger.info(f"Found {len(libraries_with_versions)} libraries with version information for analysis")
            
        print("\n" + "="*80)
        print("📚 LIBRARY VERSION ANALYSIS")
        print("="*80)
        
        # Group libraries by security risk and also include libraries without risk assessment
        critical_libs = [lib for lib in libraries_with_versions if lib.security_risk == "CRITICAL"]
        high_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk == "HIGH"]
        medium_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk == "MEDIUM"]
        low_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk in ["LOW", None]]
        
        # Also show ALL libraries with versions, even if version analysis failed
        all_versioned_libs = libraries_with_versions
        
        self.logger.info(f"Version analysis grouping: Critical={len(critical_libs)}, High={len(high_risk_libs)}, Medium={len(medium_risk_libs)}, Low={len(low_risk_libs)}, Total={len(all_versioned_libs)}")
        
        # Print critical libraries first
        if critical_libs:
            print(f"\n⚠️  CRITICAL RISK LIBRARIES ({len(critical_libs)}):")
            print("-" * 40)
            for lib in sorted(critical_libs, key=lambda x: x.years_behind or 0, reverse=True):
                print(f"   {lib.format_version_output()}")
                if lib.version_recommendation:
                    print(f"   └─ {lib.version_recommendation}")
        
        # Print high risk libraries
        if high_risk_libs:
            print(f"\n⚠️  HIGH RISK LIBRARIES ({len(high_risk_libs)}):")
            print("-" * 40)
            for lib in sorted(high_risk_libs, key=lambda x: x.years_behind or 0, reverse=True):
                print(f"   {lib.format_version_output()}")
                if lib.version_recommendation:
                    print(f"   └─ {lib.version_recommendation}")
        
        # Print medium risk libraries
        if medium_risk_libs:
            print(f"\n⚠️  MEDIUM RISK LIBRARIES ({len(medium_risk_libs)}):")
            print("-" * 40)
            for lib in sorted(medium_risk_libs, key=lambda x: x.years_behind or 0, reverse=True):
                print(f"   {lib.format_version_output()}")
        
        # Print low risk libraries (summary only)
        if low_risk_libs:
            current_libs = [lib for lib in low_risk_libs if (lib.years_behind or 0) < 0.5]
            outdated_libs = [lib for lib in low_risk_libs if (lib.years_behind or 0) >= 0.5]
            
            if outdated_libs:
                print(f"\n📋 OUTDATED LIBRARIES ({len(outdated_libs)}):")
                print("-" * 40)
                for lib in sorted(outdated_libs, key=lambda x: x.years_behind or 0, reverse=True):
                    print(f"   {lib.format_version_output()}")
            
            if current_libs:
                print(f"\n✅ CURRENT LIBRARIES ({len(current_libs)}):")
                print("-" * 40)
                for lib in sorted(current_libs, key=lambda x: x.name):
                    print(f"   {lib.format_version_output()}")
        
        # ALWAYS show all libraries with versions, even if risk analysis failed
        if all_versioned_libs and not (critical_libs or high_risk_libs or medium_risk_libs):
            print(f"\n📚 ALL LIBRARIES WITH VERSION INFO ({len(all_versioned_libs)}):")
            print("-" * 60)
            for lib in sorted(all_versioned_libs, key=lambda x: x.name.lower()):
                formatted = lib.format_version_output()
                print(f"   {formatted}")
                
                # Show additional info if available
                if hasattr(lib, 'latest_version') and lib.latest_version and lib.latest_version != lib.version:
                    print(f"   └─ Latest available: {lib.latest_version}")
                if lib.version_recommendation and "Unable to determine" not in lib.version_recommendation:
                    print(f"   └─ {lib.version_recommendation}")
        
        # Print summary statistics
        total_libs = len(libraries_with_versions)
        if total_libs > 0:
            print("\n📊 SUMMARY:")
            print("-" * 40)
            print(f"   Total libraries analyzed: {total_libs}")
            print(f"   Critical risk: {len(critical_libs)}")
            print(f"   High risk: {len(high_risk_libs)}")  
            print(f"   Medium risk: {len(medium_risk_libs)}")
            print(f"   Low risk: {len(low_risk_libs)}")
            
            libs_with_years = [lib for lib in libraries_with_versions if lib.years_behind is not None]
            if libs_with_years:
                avg_years = sum(lib.years_behind for lib in libs_with_years) / len(libs_with_years)
                print(f"   Average years behind: {avg_years:.1f}")
        
        print("="*80)