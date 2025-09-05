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
Heuristic Detection Engine for Library Detection.

Specialized engine for heuristic-based library detection using known patterns.
Handles timing, error management, and result processing for heuristic detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import Any

from dexray_insight.core.base_classes import AnalysisContext


class HeuristicDetectionEngine:
    """
    Specialized engine for heuristic-based library detection.

    Single Responsibility: Handle heuristic detection with timing and error management.
    """

    def __init__(self, parent_module):
        """Initialize HeuristicDetectionEngine with parent module."""
        self.parent = parent_module
        self.logger = parent_module.logger

    def execute_detection(self, context: AnalysisContext, analysis_errors: list[str]) -> dict[str, Any]:
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

            return {"libraries": detected_libraries, "execution_time": execution_time, "success": True}

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Heuristic detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)

            return {"libraries": [], "execution_time": execution_time, "success": False}
