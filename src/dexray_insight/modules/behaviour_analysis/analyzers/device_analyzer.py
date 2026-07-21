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

"""Device Information Analyzer.

Detects when applications attempt to access device-specific information
such as device model, Android ID, and hardware identifiers.
"""

import logging

from ..models.behavior_evidence import BehaviorEvidence


class DeviceAnalyzer:
    """Analyzer for device information access behaviors."""

    DEVICE_PATTERNS = [
        r"android\.os\.Build\.MODEL",
        r"Build\.MODEL",
        r"getSystemService.*DEVICE_POLICY_SERVICE",
        r"getModel\(\)",
        r"android\.provider\.Settings\.Secure\.ANDROID_ID",
    ]

    def __init__(self, logger: logging.Logger | None = None):
        """Initialize DeviceAnalyzer with optional logger."""
        self.logger = logger or logging.getLogger(__name__)

    def analyze_device_model_access(
        self, apk_obj, dex_obj, dx_obj, result, search_engine=None
    ) -> list[BehaviorEvidence]:
        """Check if app accesses device model information."""
        evidence = []

        try:
            # Search in DEX strings and smali code via the shared engine so the
            # string pool / smali corpus are built once and reused. Semantics
            # (and BehaviorEvidence provenance) are identical to the previous
            # inline scan.
            if search_engine is None:
                from ..engines.pattern_search_engine import PatternSearchEngine

                search_engine = PatternSearchEngine(self.logger)

            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.DEVICE_PATTERNS, "device model access"
            )

            # Add finding to result
            result.add_finding(
                "device_model_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application attempts to access device model information",
            )

            return evidence

        except Exception as e:
            self.logger.error(f"Device model analysis failed: {e}")
            return []

    def analyze_android_version_access(
        self, apk_obj, dex_obj, dx_obj, result, search_engine=None
    ) -> list[BehaviorEvidence]:
        """Check if app accesses Android version information."""
        evidence = []
        patterns = [
            r"android\.os\.Build\.VERSION",
            r"Build\.VERSION",
            r"SDK_INT",
            r"RELEASE",
            r"getSystemProperty.*version",
        ]

        try:
            # Import here to avoid circular imports
            if search_engine is None:
                from ..engines.pattern_search_engine import PatternSearchEngine

                search_engine = PatternSearchEngine(self.logger)

            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, patterns, "Android version access"
            )

            result.add_finding(
                "android_version_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application accesses Android version information",
            )

            return evidence

        except Exception as e:
            self.logger.error(f"Android version analysis failed: {e}")
            return []
