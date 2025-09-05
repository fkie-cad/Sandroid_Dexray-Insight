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
Pattern Search Engine.

Provides centralized pattern matching capabilities for behavior analysis.
Handles searching through DEX strings, smali code, and other APK components.
"""

import logging
import re
from typing import Optional

from ..models.behavior_evidence import BehaviorEvidence


class PatternSearchEngine:
    """Centralized pattern search engine for behavior analysis."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize PatternSearchEngine with optional logger."""
        self.logger = logger or logging.getLogger(__name__)

    def search_patterns_in_apk(
        self, apk_obj, dex_obj, dx_obj, patterns: list[str], feature_name: str
    ) -> list[BehaviorEvidence]:
        """Search patterns in APK strings and code."""
        evidence = []

        try:
            # Search in DEX strings
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        dex_strings = dex.get_strings()
                        for string in dex_strings:
                            string_val = str(string)
                            for pattern in patterns:
                                if re.search(pattern, string_val, re.IGNORECASE):
                                    evidence.append(
                                        BehaviorEvidence(
                                            type="string",
                                            content=string_val,
                                            pattern_matched=pattern,
                                            location=f"DEX {i+1} strings",
                                            dex_index=i,
                                        )
                                    )
                    except Exception as e:
                        self.logger.debug(f"Error analyzing {feature_name} in DEX strings {i}: {e}")

            # Search in smali code
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        for cls in dex.get_classes():
                            class_source = cls.get_source()
                            if class_source:
                                for pattern in patterns:
                                    matches = re.finditer(pattern, class_source, re.IGNORECASE)
                                    for match in matches:
                                        # Get line number context
                                        lines = class_source[: match.start()].count("\n")
                                        evidence.append(
                                            BehaviorEvidence(
                                                type="code",
                                                content=match.group(),
                                                pattern_matched=pattern,
                                                class_name=cls.get_name(),
                                                line_number=lines + 1,
                                                dex_index=i,
                                            )
                                        )
                    except Exception as e:
                        self.logger.debug(f"Error analyzing {feature_name} in smali DEX {i}: {e}")

            return evidence

        except Exception as e:
            self.logger.error(f"Pattern search failed for {feature_name}: {e}")
            return []

    def search_in_strings(self, dex_obj, patterns: list[str], feature_name: str) -> list[BehaviorEvidence]:
        """Search patterns only in DEX strings."""
        evidence = []

        if not dex_obj:
            return evidence

        try:
            for i, dex in enumerate(dex_obj):
                try:
                    dex_strings = dex.get_strings()
                    for string in dex_strings:
                        string_val = str(string)
                        for pattern in patterns:
                            if re.search(pattern, string_val, re.IGNORECASE):
                                evidence.append(
                                    BehaviorEvidence(
                                        type="string",
                                        content=string_val,
                                        pattern_matched=pattern,
                                        location=f"DEX {i+1} strings",
                                        dex_index=i,
                                    )
                                )
                except Exception as e:
                    self.logger.debug(f"Error searching strings in DEX {i} for {feature_name}: {e}")

        except Exception as e:
            self.logger.error(f"String search failed for {feature_name}: {e}")

        return evidence

    def search_in_code(self, dex_obj, patterns: list[str], feature_name: str) -> list[BehaviorEvidence]:
        """Search patterns only in smali code."""
        evidence = []

        if not dex_obj:
            return evidence

        try:
            for i, dex in enumerate(dex_obj):
                try:
                    for cls in dex.get_classes():
                        class_source = cls.get_source()
                        if class_source:
                            for pattern in patterns:
                                matches = re.finditer(pattern, class_source, re.IGNORECASE)
                                for match in matches:
                                    # Get line number context
                                    lines = class_source[: match.start()].count("\n")
                                    evidence.append(
                                        BehaviorEvidence(
                                            type="code",
                                            content=match.group(),
                                            pattern_matched=pattern,
                                            class_name=cls.get_name(),
                                            line_number=lines + 1,
                                            dex_index=i,
                                        )
                                    )
                except Exception as e:
                    self.logger.debug(f"Error searching code in DEX {i} for {feature_name}: {e}")

        except Exception as e:
            self.logger.error(f"Code search failed for {feature_name}: {e}")

        return evidence

    def check_permissions(self, apk_obj, permission_list: list[str]) -> list[BehaviorEvidence]:
        """Check for specific permissions in the APK."""
        evidence = []

        try:
            permissions = apk_obj.get_permissions()
            for permission in permission_list:
                if permission in permissions:
                    evidence.append(
                        BehaviorEvidence(type="permission", content=permission, location="AndroidManifest.xml")
                    )
        except Exception as e:
            self.logger.error(f"Permission check failed: {e}")

        return evidence
