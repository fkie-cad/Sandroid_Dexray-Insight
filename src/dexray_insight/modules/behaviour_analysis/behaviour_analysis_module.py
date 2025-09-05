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

"""Behaviour Analysis Module - Refactored.

Main coordinator for behavioral analysis with fast/deep modes.
Delegates specific analysis tasks to specialized submodules.
"""

import logging
import time
from typing import Any

from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.core.base_classes import AnalysisStatus
from dexray_insight.core.base_classes import BaseAnalysisModule
from dexray_insight.core.base_classes import register_module
from dexray_insight.results.BehaviourAnalysisResults import BehaviourAnalysisResults

# Import specialized analyzers
from .analyzers.device_analyzer import DeviceAnalyzer
from .analyzers.media_analyzer import MediaAnalyzer
from .analyzers.reflection_analyzer import ReflectionAnalyzer
from .analyzers.system_analyzer import SystemAnalyzer
from .analyzers.telephony_analyzer import TelephonyAnalyzer
from .modes.fast_mode_analyzer import FastModeAnalyzer

# Import modes and engines
from .modes.mode_manager import ModeManager

# Import models


@register_module("behaviour_analysis")
class BehaviourAnalysisModule(BaseAnalysisModule):
    """Refactored module for behavioral analysis with specialized components."""

    def __init__(self, config: dict[str, Any]):
        """Initialize BehaviourAnalysisModule with specialized analyzers."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Initialize specialized components
        self.mode_manager = ModeManager(config, self.logger)
        self.fast_mode_analyzer = FastModeAnalyzer(self.logger)

        # Initialize deep mode analyzers
        self.device_analyzer = DeviceAnalyzer(self.logger)
        self.telephony_analyzer = TelephonyAnalyzer(self.logger)
        self.system_analyzer = SystemAnalyzer(self.logger)
        self.media_analyzer = MediaAnalyzer(self.logger)
        self.reflection_analyzer = ReflectionAnalyzer(self.logger)

    def get_name(self) -> str:
        """Get the module name."""
        return "Behaviour Analysis"

    def get_description(self) -> str:
        """Get the module description."""
        return "Performs behavioral analysis to detect privacy-sensitive behaviors. Supports fast mode (APK only) and deep mode (full DEX analysis)"

    def get_dependencies(self) -> list[str]:
        """Get module dependencies."""
        return ["apk_overview"]

    def get_priority(self) -> int:
        """Get module priority."""
        return 1000

    def analyze(self, apk_path: str, context: AnalysisContext) -> BehaviourAnalysisResults:
        """Coordinate behavioral analysis using specialized components.

        Args:
            apk_path: Path to APK file
            context: Analysis context

        Returns:
            BehaviourAnalysisResults with behavioral findings
        """
        start_time = time.time()

        try:
            # Check if module is enabled
            if not self.mode_manager.is_module_enabled(context):
                return BehaviourAnalysisResults(
                    module_name="behaviour_analysis",
                    status=AnalysisStatus.SKIPPED,
                    error_message="Behaviour analysis module disabled in configuration",
                    execution_time=time.time() - start_time,
                )

            # Determine analysis mode
            is_deep_mode, mode_str = self.mode_manager.determine_analysis_mode(context)
            self.logger.info(f"Starting behaviour analysis in {mode_str} mode...")

            # Validate androguard object availability
            if not context.androguard_obj:
                return BehaviourAnalysisResults(
                    module_name="behaviour_analysis",
                    status=AnalysisStatus.FAILURE,
                    error_message="Androguard object not available in context",
                    execution_time=time.time() - start_time,
                )

            # Prepare analysis objects
            analysis_objects = self.mode_manager.prepare_analysis_objects(context, is_deep_mode)

            # Initialize result
            result = BehaviourAnalysisResults(
                module_name="behaviour_analysis", status=AnalysisStatus.SUCCESS, execution_time=0.0
            )

            # Store analysis objects in result for security analysis access
            self.mode_manager.store_analysis_objects_in_result(result, analysis_objects)

            # Perform analysis based on mode
            if is_deep_mode:
                self._perform_deep_analysis(analysis_objects, result)
            else:
                self._perform_fast_analysis(analysis_objects, result)

            # Generate summary
            result.summary = self.mode_manager.generate_analysis_summary(result, is_deep_mode)

            result.execution_time = time.time() - start_time
            detected_count = len(result.get_detected_features())
            total_count = len(result.findings)

            self.logger.info(
                f"Behaviour analysis ({mode_str} mode) completed in {result.execution_time:.2f}s - {detected_count}/{total_count} behaviors detected"
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Behaviour analysis failed: {str(e)}")

            return BehaviourAnalysisResults(
                module_name="behaviour_analysis",
                status=AnalysisStatus.FAILURE,
                error_message=str(e),
                execution_time=execution_time,
            )

    def _perform_deep_analysis(self, analysis_objects: dict[str, Any], result: BehaviourAnalysisResults) -> None:
        """Perform deep analysis using all available analyzers."""
        apk_obj = analysis_objects["apk_obj"]
        dex_obj = analysis_objects["dex_obj"]
        dx_obj = analysis_objects["dx_obj"]

        try:
            # Device information analysis
            self.device_analyzer.analyze_device_model_access(apk_obj, dex_obj, dx_obj, result)
            self.device_analyzer.analyze_android_version_access(apk_obj, dex_obj, dx_obj, result)

            # Telephony analysis
            self.telephony_analyzer.analyze_imei_access(apk_obj, dex_obj, dx_obj, result)
            self.telephony_analyzer.analyze_phone_number_access(apk_obj, dex_obj, dx_obj, result)

            # System analysis
            self.system_analyzer.analyze_clipboard_usage(apk_obj, dex_obj, dx_obj, result)
            self.system_analyzer.analyze_dynamic_receivers(apk_obj, dex_obj, dx_obj, result)
            self.system_analyzer.analyze_running_services_access(apk_obj, dex_obj, dx_obj, result)
            self.system_analyzer.analyze_installed_applications(apk_obj, dex_obj, dx_obj, result)
            self.system_analyzer.analyze_installed_packages(apk_obj, dex_obj, dx_obj, result)

            # Media analysis
            self.media_analyzer.analyze_camera_access(apk_obj, dex_obj, dx_obj, result)

            # Reflection analysis
            self.reflection_analyzer.analyze_reflection_usage(apk_obj, dex_obj, dx_obj, result)

        except Exception as e:
            self.logger.error(f"Deep analysis failed: {e}")
            raise

    def _perform_fast_analysis(self, analysis_objects: dict[str, Any], result: BehaviourAnalysisResults) -> None:
        """Perform fast analysis using only APK object."""
        apk_obj = analysis_objects["apk_obj"]

        try:
            # Basic permission analysis
            self.fast_mode_analyzer.analyze_basic_permissions(apk_obj, result)

            # Basic component analysis
            self.fast_mode_analyzer.analyze_basic_components(apk_obj, result)

            # App metadata analysis
            self.fast_mode_analyzer.analyze_app_metadata(apk_obj, result)

        except Exception as e:
            self.logger.error(f"Fast analysis failed: {e}")
            raise
