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
Pattern Detector for Tracker Analysis.

Specialized detector for pattern-based tracker detection using regex matching
against code signatures and network patterns.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

import logging
import re
from typing import Any

from dexray_insight.core.base_classes import AnalysisContext

from ..models import DetectedTracker


class PatternDetector:
    """
    Specialized detector for pattern-based tracker detection.

    Single Responsibility: Handle regex pattern matching against code signatures
    and network patterns with detailed location tracking.
    """

    def __init__(self):
        """Initialize PatternDetector with logger."""
        self.logger = logging.getLogger(__name__)

    def detect_tracker_patterns(
        self, tracker_name: str, tracker_info: dict[str, Any], strings: set[str], context: AnalysisContext
    ) -> list[DetectedTracker]:
        """
        Check if tracker patterns match in the strings.

        Args:
            tracker_name: Name of the tracker to check
            tracker_info: Tracker configuration with patterns and metadata
            strings: Set of strings to search through
            context: Analysis context with location information

        Returns:
            List of detected trackers (empty if no matches)
        """
        patterns = tracker_info.get("patterns", [])
        version_patterns = tracker_info.get("version_patterns", [])
        network_patterns = tracker_info.get("network_patterns", [])

        matches = []
        detailed_locations = []

        # Check code patterns
        code_matches = self._check_patterns(patterns, strings, context, detailed_locations)
        matches.extend(code_matches)

        # Check network patterns
        network_matches = self._check_patterns(network_patterns, strings, context, detailed_locations)
        matches.extend(network_matches)

        # If matches found, create tracker detection
        if matches:
            # Try to extract version information (lazy import to avoid circular imports)
            from .version_extractor import VersionExtractor

            version_extractor = VersionExtractor()
            version = version_extractor.extract_version(matches, version_patterns)

            tracker = DetectedTracker(
                name=tracker_name,
                version=version,
                description=tracker_info.get("description", ""),
                category=tracker_info.get("category", "Unknown"),
                website=tracker_info.get("website", ""),
                code_signature="|".join(patterns),
                network_signature="|".join(network_patterns),
                detection_method="Built-in Database",
                locations=list(set(detailed_locations))[:10],  # Deduplicate and limit
                confidence=1.0,
            )
            return [tracker]

        return []

    def _check_patterns(
        self, patterns: list[str], strings: set[str], context: AnalysisContext, detailed_locations: list[str]
    ) -> list[str]:
        """
        Check a list of patterns against the string set.

        Args:
            patterns: List of regex patterns to check
            strings: Set of strings to search through
            context: Analysis context with location information
            detailed_locations: List to append location details to

        Returns:
            List of matched strings
        """
        matches = []

        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for string in strings:
                    if regex.search(string):
                        matches.append(string)
                        # Add location details if available
                        if hasattr(context, "string_locations") and string in context.string_locations:
                            for location in context.string_locations[string][:3]:  # Limit to 3 locations per string
                                detailed_locations.append(f"{string} -> {location}")
                        else:
                            detailed_locations.append(string)
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern: {pattern} - {str(e)}")

        return matches

    def detect_exodus_patterns(
        self, tracker_info: dict[str, Any], strings: set[str], context: AnalysisContext
    ) -> list[DetectedTracker]:
        """
        Detect trackers using Exodus Privacy patterns.

        Args:
            tracker_info: Exodus tracker information with signatures
            strings: Set of strings to search through
            context: Analysis context with location information

        Returns:
            List of detected trackers (empty if no matches)
        """
        code_signature = tracker_info.get("code_signature", "")
        network_signature = tracker_info.get("network_signature", "")

        if not code_signature and not network_signature:
            return []

        code_matches = []
        network_matches = []
        detailed_locations = []

        # Check code signatures
        if code_signature:
            code_matches = self._check_single_pattern(code_signature, strings, context, detailed_locations, "code")

        # Check network signatures
        if network_signature:
            network_matches = self._check_single_pattern(
                network_signature, strings, context, detailed_locations, "network"
            )

        # If matches found, create detection
        if code_matches or network_matches:
            tracker = DetectedTracker(
                name=tracker_info["name"],
                description=tracker_info.get("description", ""),
                category=tracker_info.get("category", "Unknown"),
                website=tracker_info.get("website", ""),
                code_signature=code_signature,
                network_signature=network_signature,
                detection_method="Exodus Privacy API",
                locations=detailed_locations[:10],  # Limit to first 10 detailed locations
                confidence=0.9,  # Slightly lower confidence for Exodus patterns
            )
            return [tracker]

        return []

    def _check_single_pattern(
        self,
        pattern: str,
        strings: set[str],
        context: AnalysisContext,
        detailed_locations: list[str],
        pattern_type: str,
    ) -> list[str]:
        """
        Check a single pattern against the string set.

        Args:
            pattern: Regex pattern to check
            strings: Set of strings to search through
            context: Analysis context with location information
            detailed_locations: List to append location details to
            pattern_type: Type of pattern for logging (code/network)

        Returns:
            List of matched strings
        """
        matches = []

        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for string in strings:
                if regex.search(string):
                    matches.append(string)
                    # Add location details if available
                    if hasattr(context, "string_locations") and string in context.string_locations:
                        for location in context.string_locations[string][:3]:  # Limit to 3 locations per string
                            detailed_locations.append(f"{string} -> {location}")
                    else:
                        detailed_locations.append(string)
        except re.error as e:
            self.logger.warning(f"Invalid {pattern_type} regex pattern: {pattern} - {str(e)}")

        return matches
