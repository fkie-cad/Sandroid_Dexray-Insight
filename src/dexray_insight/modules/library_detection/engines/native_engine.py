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
Native Library Detection Engine for Library Detection.

Specialized engine for native library detection (.so files).
Handles timing, error management, and result processing for native library detection.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import time
from typing import Any

from dexray_insight.core.base_classes import AnalysisContext


class NativeLibraryDetectionEngine:
    """
    Specialized engine for native library detection.

    Single Responsibility: Handle native (.so) library detection with timing and error management.
    """

    def __init__(self, parent_module):
        """Initialize NativeLibraryDetectionEngine with parent module."""
        self.parent = parent_module
        self.logger = parent_module.logger

    def execute_detection(self, context: AnalysisContext, analysis_errors: list[str]) -> dict[str, Any]:
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

            return {"libraries": detected_libraries, "execution_time": execution_time, "success": True}

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Native library detection failed: {str(e)}"
            self.logger.error(error_msg)
            analysis_errors.append(error_msg)

            return {"libraries": [], "execution_time": execution_time, "success": False}
