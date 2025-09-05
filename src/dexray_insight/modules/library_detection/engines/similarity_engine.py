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
Similarity Detection Engine for Library Detection.

Specialized engine for similarity-based library detection using LibScan-style analysis.
Handles timing, error management, and result processing for similarity detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import Any

from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.results.LibraryDetectionResults import DetectedLibrary


class SimilarityDetectionEngine:
    """
    Specialized engine for similarity-based library detection.

    Single Responsibility: Handle LibScan-style similarity detection with timing and error management.
    """

    def __init__(self, parent_module):
        """Initialize SimilarityDetectionEngine with parent module."""
        self.parent = parent_module
        self.logger = parent_module.logger

    def execute_detection(
        self, context: AnalysisContext, analysis_errors: list[str], existing_libraries: list[DetectedLibrary]
    ) -> dict[str, Any]:
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

            self.logger.info(
                f"Stage 2 detected {len(detected_libraries)} additional libraries using similarity analysis"
            )

            return {"libraries": detected_libraries, "execution_time": execution_time, "success": True}

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Similarity detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)

            return {"libraries": [], "execution_time": execution_time, "success": False}
