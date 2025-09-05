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
Reflection Analyzer.

Detects when applications use Java reflection, which can be used
to bypass security restrictions or obfuscate functionality.
"""

import logging
from typing import Optional

from ..models.behavior_evidence import BehaviorEvidence


class ReflectionAnalyzer:
    """Analyzer for Java reflection usage."""

    REFLECTION_PATTERNS = [
        r"Class\.forName\(",
        r"getDeclaredMethod\(",
        r"getMethod\(",
        r"invoke\(",
        r"java\.lang\.reflect",
        r"Method\.invoke\(",
        r"getDeclaredField\(",
        r"getField\(",
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize ReflectionAnalyzer with optional logger."""
        self.logger = logger or logging.getLogger(__name__)

    def analyze_reflection_usage(self, apk_obj, dex_obj, dx_obj, result) -> list[BehaviorEvidence]:
        """Check if app uses reflection."""
        try:
            from ..engines.pattern_search_engine import PatternSearchEngine

            search_engine = PatternSearchEngine(self.logger)
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.REFLECTION_PATTERNS, "reflection usage"
            )

            result.add_finding(
                "reflection_usage",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application uses Java reflection",
            )

            return evidence

        except Exception as e:
            self.logger.error(f"Reflection analysis failed: {e}")
            return []
