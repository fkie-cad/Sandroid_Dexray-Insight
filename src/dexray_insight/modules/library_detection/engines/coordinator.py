#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""
Library Detection Coordinator.

Coordinator class for orchestrating all detection engines and aggregating results.
Follows Single Responsibility Principle by focusing only on coordination.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time

# Import result class - need to handle circular import
from typing import TYPE_CHECKING

from ....core.base_classes import AnalysisContext
from ....core.base_classes import AnalysisStatus
from ....results.LibraryDetectionResults import DetectedLibrary
from .androidx_engine import AndroidXDetectionEngine
from .apktool_detection_engine import ApktoolDetectionEngine
from .heuristic_engine import HeuristicDetectionEngine
from .native_engine import NativeLibraryDetectionEngine
from .similarity_engine import SimilarityDetectionEngine

if TYPE_CHECKING:
    from .. import LibraryDetectionResult


class LibraryDetectionCoordinator:
    """
    Coordinator class for orchestrating all detection engines.

    Single Responsibility: Coordinate detection engines and aggregate results.
    """

    def __init__(self, parent_module):
        """Initialize LibraryDetectionCoordinator with parent module and detection engines."""
        self.parent = parent_module
        self.logger = parent_module.logger

        # Initialize detection engines
        self.heuristic_engine = HeuristicDetectionEngine(parent_module)
        self.similarity_engine = SimilarityDetectionEngine(parent_module)
        self.native_engine = NativeLibraryDetectionEngine(parent_module)
        self.androidx_engine = AndroidXDetectionEngine(parent_module)
        self.apktool_engine = ApktoolDetectionEngine(parent_module.config, parent_module.logger)

    def execute_full_analysis(self, apk_path: str, context: AnalysisContext) -> "LibraryDetectionResult":
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
                stage1_libraries = heuristic_result["libraries"]
                detected_libraries.extend(stage1_libraries)
                stage_timings["stage1_time"] = heuristic_result["execution_time"]
            else:
                stage_timings["stage1_time"] = 0.0

            # Stage 2: Similarity Detection
            if self.parent.enable_stage2:
                similarity_result = self.similarity_engine.execute_detection(
                    context, analysis_errors, detected_libraries
                )
                stage2_libraries = similarity_result["libraries"]
                detected_libraries.extend(stage2_libraries)
                stage_timings["stage2_time"] = similarity_result["execution_time"]
            else:
                stage_timings["stage2_time"] = 0.0

            # Stage 3: Native Library Detection
            native_result = self.native_engine.execute_detection(context, analysis_errors)
            native_libraries = native_result["libraries"]
            detected_libraries.extend(native_libraries)
            stage_timings["stage3_time"] = native_result["execution_time"]

            # Stage 4: AndroidX Detection
            androidx_result = self.androidx_engine.execute_detection(context, analysis_errors)
            androidx_libraries = androidx_result["libraries"]
            detected_libraries.extend(androidx_libraries)
            stage_timings["stage4_time"] = androidx_result["execution_time"]

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

            # Stage 6: Native Library Version Detection Integration with Version Analysis
            try:
                self.logger.debug(
                    f"Library Detection: Starting native library integration. Current library count: {len(detected_libraries)}"
                )
                native_version_libraries = self._integrate_native_library_results(context, analysis_errors)
                if native_version_libraries:
                    # Apply version analysis to native libraries if they have version information
                    self._apply_version_analysis_to_libraries(native_version_libraries, context)
                    detected_libraries.extend(native_version_libraries)
                    self.logger.info(
                        f"Library Detection: Integrated {len(native_version_libraries)} native libraries with version information"
                    )
                    self.logger.info(
                        f"Library Detection: Total library count after native integration: {len(detected_libraries)}"
                    )
                    for native_lib in native_version_libraries:
                        years_info = (
                            f", years_behind: {native_lib.years_behind}"
                            if hasattr(native_lib, "years_behind") and native_lib.years_behind is not None
                            else ""
                        )
                        self.logger.info(
                            f"Library Detection: Integrated native library: {native_lib.name} {native_lib.version} (confidence: {native_lib.confidence}{years_info})"
                        )
                    stage_timings["stage6_time"] = 0.0  # Integration doesn't require timing
                else:
                    self.logger.warning(
                        "Library Detection: No native library version results found in analysis context"
                    )
                    stage_timings["stage6_time"] = 0.0
            except Exception as e:
                error_msg = f"Native library integration failed: {str(e)}"
                self.logger.error(error_msg)
                analysis_errors.append(error_msg)
                stage_timings["stage6_time"] = 0.0
                import traceback

                self.logger.debug(f"Library Detection: Native integration traceback: {traceback.format_exc()}")

            # Remove duplicates
            detected_libraries = self.parent._deduplicate_libraries(detected_libraries)

            execution_time = time.time() - start_time

            self.logger.info(f"Library detection completed: {len(detected_libraries)} unique libraries detected")
            self.logger.info(
                f"Total execution time: {execution_time:.2f}s (Stage 1: {stage_timings['stage1_time']:.2f}s, Stage 2: {stage_timings['stage2_time']:.2f}s, Stage 3: {stage_timings['stage3_time']:.2f}s, Stage 4: {stage_timings['stage4_time']:.2f}s)"
            )

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
                stage1_time=stage_timings["stage1_time"],
                stage2_time=stage_timings["stage2_time"],
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
                analysis_errors=[error_msg],
            )

    def _print_version_analysis_results(self, libraries: list[DetectedLibrary], context):
        """
        Print enhanced version analysis results to console.

        Only displays when security analysis is enabled or version_analysis.security_analysis_only is False.

        Format: library name (version): smali path : years behind
        Example: Gson (2.8.5): /com/google/gson/ : 2.1 years behind
        """
        # Check if security analysis is enabled
        security_analysis_enabled = context.config.get("security", {}).get("enable_owasp_assessment", False)

        # Check version analysis configuration
        version_config = context.config.get("modules", {}).get("library_detection", {}).get("version_analysis", {})
        security_analysis_only = version_config.get("security_analysis_only", True)
        version_analysis_enabled = version_config.get("enabled", True)

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

        print("\n" + "=" * 80)
        print("📚 LIBRARY VERSION ANALYSIS")
        print("=" * 80)

        # Group libraries by security risk and also include libraries without risk assessment
        critical_libs = [lib for lib in libraries_with_versions if lib.security_risk == "CRITICAL"]
        high_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk == "HIGH"]
        medium_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk == "MEDIUM"]
        low_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk in ["LOW", None]]

        # Also show ALL libraries with versions, even if version analysis failed
        all_versioned_libs = libraries_with_versions

        self.logger.info(
            f"Version analysis grouping: Critical={len(critical_libs)}, High={len(high_risk_libs)}, Medium={len(medium_risk_libs)}, Low={len(low_risk_libs)}, Total={len(all_versioned_libs)}"
        )

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
                if hasattr(lib, "latest_version") and lib.latest_version and lib.latest_version != lib.version:
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

        print("=" * 80)

    def _integrate_native_library_results(self, context: AnalysisContext, errors: list[str]) -> list[DetectedLibrary]:
        """
        Integrate native library detection results from the analysis context.

        This method pulls native library detections that were populated by the
        native analysis module and converts them to DetectedLibrary objects.

        Args:
            context: Analysis context containing native library results
            errors: List to append any integration errors

        Returns:
            List of DetectedLibrary objects from native analysis
        """
        native_libraries = []

        try:
            # Check if native library results are available in context
            self.logger.debug("Native Integration: Checking analysis context for native library results...")
            self.logger.debug(
                f"Native Integration: Available module results keys: {list(context.module_results.keys())}"
            )

            native_lib_results = context.module_results.get("native_libraries", [])

            if not native_lib_results:
                self.logger.warning("Native Integration: No native library results found in analysis context")
                self.logger.debug(f"Native Integration: Full module_results content: {context.module_results}")
                return native_libraries

            self.logger.info(f"Native Integration: Found {len(native_lib_results)} native library results in context")

            # Convert each native library result to DetectedLibrary object
            for native_lib in native_lib_results:
                try:
                    # Ensure we have the required fields
                    library_name = native_lib.get("name", "")
                    library_version = native_lib.get("version", "")

                    if not library_name:
                        self.logger.warning("Skipping native library with no name")
                        continue

                    # Map detection method from native analysis
                    detection_method = native_lib.get("detection_method", "native_unknown")
                    if detection_method.startswith("native_"):
                        method_suffix = detection_method[7:]  # Remove 'native_' prefix
                        if method_suffix == "prefix":
                            from ....results.LibraryDetectionResults import LibraryDetectionMethod

                            detection_method_enum = LibraryDetectionMethod.NATIVE_VERSION
                        else:
                            from ....results.LibraryDetectionResults import LibraryDetectionMethod

                            detection_method_enum = LibraryDetectionMethod.NATIVE
                    else:
                        from ....results.LibraryDetectionResults import LibraryDetectionMethod

                        detection_method_enum = LibraryDetectionMethod.NATIVE

                    # Map category string to LibraryCategory enum
                    category_str = native_lib.get("category", "native")
                    from ....results.LibraryDetectionResults import LibraryCategory
                    from ....results.LibraryDetectionResults import LibrarySource
                    from ....results.LibraryDetectionResults import LibraryType

                    if category_str == "native":
                        category_enum = LibraryCategory.UTILITY
                        library_type_enum = LibraryType.NATIVE_LIBRARY
                    else:
                        category_enum = LibraryCategory.UNKNOWN
                        library_type_enum = LibraryType.NATIVE_LIBRARY

                    # Get architecture information
                    architecture = native_lib.get("additional_info", {}).get("architecture", "unknown")

                    # Create DetectedLibrary object
                    detected_library = DetectedLibrary(
                        name=library_name,
                        version=library_version,
                        detection_method=detection_method_enum,
                        category=category_enum,
                        library_type=library_type_enum,
                        confidence=native_lib.get("confidence", 0.8),
                        evidence=[
                            f"Native compilation artifact: {native_lib.get('source_evidence', 'N/A')}",
                            f"Source type: {native_lib.get('additional_info', {}).get('source_type', 'unknown')}",
                            f"File: {native_lib.get('file_path', 'N/A')}",
                            f"Architecture: {architecture}",
                        ],
                        architectures=[architecture] if architecture != "unknown" else [],
                        file_paths=[native_lib.get("file_path", "")] if native_lib.get("file_path") else [],
                        source=LibrarySource.NATIVE_LIBS,
                        location=native_lib.get("file_path", ""),
                        description=f"Native library detected from compilation artifacts ({native_lib.get('additional_info', {}).get('source_type', 'unknown')})",
                    )

                    native_libraries.append(detected_library)

                    self.logger.debug(
                        f"Integrated native library: {library_name} {library_version} "
                        f"(confidence: {native_lib.get('confidence', 0.8):.2f})"
                    )

                except Exception as e:
                    error_msg = f"Error processing native library result: {str(e)}"
                    self.logger.warning(error_msg)
                    errors.append(error_msg)

        except Exception as e:
            error_msg = f"Error integrating native library results: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)

        return native_libraries

    def _apply_version_analysis_to_libraries(self, libraries: list[DetectedLibrary], context: AnalysisContext):
        """
        Apply version analysis to a list of detected libraries.

        Args:
            libraries: List of DetectedLibrary objects to enhance with version analysis
            context: Analysis context containing configuration
        """
        try:
            # Check if security analysis is enabled
            security_analysis_enabled = context.config.get("security", {}).get("enable_owasp_assessment", False)

            # Get library detection configuration
            lib_config = context.config.get("modules", {}).get("library_detection", {})
            version_config = lib_config.get("version_analysis", {})

            # Import version analyzer
            from ..utils.version_analyzer import get_version_analyzer

            # Create version analyzer with proper security context
            version_analyzer = get_version_analyzer(
                {"version_analysis": version_config}, security_analysis_enabled=security_analysis_enabled
            )

            self.logger.debug(
                f"Version analyzer configured for native libraries: security_enabled={security_analysis_enabled}, "
                f"security_only={version_analyzer.security_analysis_only}, "
                f"enabled={version_analyzer.enable_version_checking}"
            )

            # Apply version analysis to each library that has version information
            for library in libraries:
                if library.version:
                    try:
                        self.logger.debug(
                            f"Applying version analysis to native library: {library.name} v{library.version}"
                        )

                        # Use package_name as primary identifier for version analysis (better for mappings)
                        # Fall back to display name if no package_name available
                        identifier_name = library.package_name if library.package_name else library.name

                        # Perform version analysis
                        analysis = version_analyzer.analyze_library_version(
                            identifier_name, library.version, library.package_name
                        )

                        self.logger.debug(
                            f"Native library version analysis result: {library.name} -> "
                            f"years_behind={analysis.years_behind}, risk={analysis.security_risk}"
                        )

                        # Update library with analysis results
                        library.years_behind = analysis.years_behind
                        library.major_versions_behind = analysis.major_versions_behind
                        library.security_risk = analysis.security_risk
                        library.version_recommendation = analysis.recommendation
                        if analysis.analysis_date:
                            library.version_analysis_date = analysis.analysis_date.isoformat()
                        library.latest_version = analysis.latest_version

                        # Update risk level based on version analysis
                        from ....results.LibraryDetectionResults import RiskLevel

                        if analysis.security_risk == "CRITICAL":
                            library.risk_level = RiskLevel.CRITICAL
                        elif analysis.security_risk == "HIGH":
                            library.risk_level = RiskLevel.HIGH
                        elif analysis.security_risk == "MEDIUM" and library.risk_level == RiskLevel.LOW:
                            library.risk_level = RiskLevel.MEDIUM

                    except Exception as e:
                        self.logger.debug(f"Version analysis failed for native library {library.name}: {e}")
                else:
                    self.logger.debug(f"Skipping version analysis for {library.name} - no version information")

        except Exception as e:
            self.logger.error(f"Error applying version analysis to native libraries: {e}")
            import traceback

            self.logger.debug(f"Version analysis error traceback: {traceback.format_exc()}")
