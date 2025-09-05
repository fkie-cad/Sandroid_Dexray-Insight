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
Native Library Version Detection Module.

This module analyzes native binaries (.so files) to identify library versions
from compilation artifacts, build strings, and embedded version information.

Key Features:
- Detects --prefix= compilation flags with library paths and versions
- Identifies common native libraries (FFmpeg, OpenSSL, curl, etc.)
- Extracts version information from multiple sources
- Cross-references findings for confidence scoring
- Integrates with existing library detection system
"""

import re
import time
from dataclasses import dataclass
from typing import Any
from typing import Optional

from .base_native_module import BaseNativeModule
from .base_native_module import NativeAnalysisResult
from .base_native_module import NativeBinaryInfo


@dataclass
class NativeLibraryDetection:
    """Represents a detected native library with version information."""

    library_name: str
    version: str
    confidence: float
    source_type: str  # 'prefix', 'version_string', 'build_info', 'cross_reference'
    source_evidence: str
    file_path: str
    additional_info: dict[str, Any] = None

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.additional_info is None:
            self.additional_info = {}


class NativeLibraryVersionModule(BaseNativeModule):
    """
    Native module for detecting library versions from compilation artifacts.

    This module analyzes strings extracted from native binaries to identify:
    1. Compilation flags (--prefix=, --enable-*, etc.)
    2. Library version strings
    3. Build information
    4. Cross-references multiple sources for confidence scoring
    """

    def __init__(self, config: dict[str, Any], logger: Optional[Any] = None):
        """Initialize NativeLibraryVersionModule with configuration."""
        super().__init__(config, logger)

        # Configuration
        self.enabled = config.get("enabled", True)
        self.min_confidence = config.get("min_confidence", 0.6)
        self.max_libraries_per_binary = config.get("max_libraries_per_binary", 10)

        # Initialize detection patterns
        self._initialize_patterns()

    def _initialize_patterns(self):
        """Initialize detection patterns for various libraries and version formats."""
        # --prefix= pattern for compilation flags
        self.prefix_pattern = re.compile(r"--prefix=([^\s]+)", re.IGNORECASE)

        # Library-version patterns commonly found in --prefix paths
        self.library_path_patterns = {
            "FFmpeg": [
                re.compile(r"/([Ff][Ff][Mm][Pp][Ee][Gg])-?([nv]?)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"/([Ff][Ff][Mm][Pp][Ee][Gg])[/-]([nv]?)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "OpenSSL": [
                re.compile(r"/([Oo][Pp][Ee][Nn][Ss][Ss][Ll])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"/([Oo][Pp][Ee][Nn][Ss][Ss][Ll])[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "curl": [
                re.compile(r"/([Cc][Uu][Rr][Ll])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"/([Cc][Uu][Rr][Ll])[/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "libpng": [
                re.compile(r"/([Ll][Ii][Bb][Pp][Nn][Gg])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"/([Pp][Nn][Gg])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "zlib": [
                re.compile(r"/([Zz][Ll][Ii][Bb])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "x264": [
                re.compile(r"/([Ll][Ii][Bb])?([Xx]264)[-_]?([Ss][Tt][Aa][Bb][Ll][Ee]|\d+)", re.IGNORECASE),
            ],
            "lame": [
                re.compile(r"/([Ll][Aa][Mm][Ee])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "opencore-amr": [
                re.compile(r"/([Oo][Pp][Ee][Nn][Cc][Oo][Rr][Ee])-?([Aa][Mm][Rr])-?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
        }

        # Direct version string patterns in binary content
        self.version_string_patterns = {
            "FFmpeg": [
                re.compile(r"([Ff][Ff][Mm][Pp][Ee][Gg])\s+version\s+([nv]?)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"([Ff][Ff][Mm][Pp][Ee][Gg])-?([nv]?)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "OpenSSL": [
                re.compile(r"([Oo][Pp][Ee][Nn][Ss][Ss][Ll])\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"([Oo][Pp][Ee][Nn][Ss][Ss][Ll])/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
            "curl": [
                re.compile(r"([Cc][Uu][Rr][Ll])/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
                re.compile(r"([Ll][Ii][Bb][Cc][Uu][Rr][Ll])/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            ],
        }

        # Build information patterns
        self.build_info_patterns = [
            re.compile(r"--enable-version(\d+)", re.IGNORECASE),
            re.compile(r"--version=(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"built\s+on\s+.*?for\s+(\w+)", re.IGNORECASE),
        ]

    def analyze_binary(self, binary_info: NativeBinaryInfo, r2: Any) -> NativeAnalysisResult:
        """
        Analyze a native binary for library version information.

        Args:
            binary_info: Information about the binary being analyzed
            r2: r2pipe connection to the binary

        Returns:
            NativeAnalysisResult with detected library versions
        """
        start_time = time.time()

        try:
            self.logger.debug(f"Analyzing native library versions in {binary_info.file_name}")

            # Extract strings from the binary
            strings_found = []

            # Method 1: Extract strings using r2's iz command (data sections)
            strings_found.extend(self._extract_strings_iz(r2, binary_info))

            # Method 2: Extract strings using r2's izz command (all sections)
            strings_found.extend(self._extract_strings_izz(r2, binary_info))

            # Analyze strings for library version patterns
            detected_libraries = self._analyze_strings_for_libraries(strings_found, binary_info)

            # Cross-reference and build confidence scores
            final_detections = self._cross_reference_detections(detected_libraries)

            self.logger.debug(f"Found {len(final_detections)} library versions in {binary_info.file_name}")

            return NativeAnalysisResult(
                binary_info=binary_info,
                module_name=self.get_module_name(),
                success=True,
                execution_time=time.time() - start_time,
                additional_data={
                    "detected_libraries": [
                        {
                            "library_name": lib.library_name,
                            "version": lib.version,
                            "confidence": lib.confidence,
                            "source_type": lib.source_type,
                            "source_evidence": lib.source_evidence,
                            "additional_info": lib.additional_info,
                        }
                        for lib in final_detections
                    ],
                    "total_detections": len(final_detections),
                },
            )

        except Exception as e:
            self.logger.error(f"Native library version analysis failed for {binary_info.file_name}: {e}")
            return NativeAnalysisResult(
                binary_info=binary_info,
                module_name=self.get_module_name(),
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )

    def _extract_strings_iz(self, r2: Any, binary_info: NativeBinaryInfo) -> list[str]:
        """Extract strings from data sections using r2's iz command."""
        try:
            result = r2.cmd("iz")
            strings = []
            for line in result.split("\n"):
                if line.strip() and not line.startswith("nth") and not line.startswith("―"):
                    # Parse r2 iz output format: nth paddr vaddr len size section type string
                    parts = line.split()
                    if len(parts) >= 7 and parts[0].isdigit():
                        # Find the type indicator (ascii, utf8, etc.)
                        type_index = None
                        for i, part in enumerate(parts):
                            if part in ["ascii", "utf8", "utf16", "utf32"]:
                                type_index = i
                                break

                        if type_index is not None and type_index + 1 < len(parts):
                            # Extract string content after the type indicator
                            string_content = " ".join(parts[type_index + 1 :])
                            if len(string_content) >= 4:  # Minimum length filter
                                strings.append(string_content)
            return strings
        except Exception as e:
            self.logger.debug(f"Failed to extract iz strings: {e}")
            return []

    def _extract_strings_izz(self, r2: Any, binary_info: NativeBinaryInfo) -> list[str]:
        """Extract strings from all sections using r2's izz command."""
        try:
            result = r2.cmd("izz")
            strings = []
            for line in result.split("\n"):
                if line.strip() and not line.startswith("nth") and not line.startswith("―"):
                    # Parse r2 izz output format: nth paddr vaddr len size section type string
                    parts = line.split()
                    if len(parts) >= 8 and parts[0].isdigit():
                        # Find the type indicator (ascii, utf8, etc.)
                        type_index = None
                        for i, part in enumerate(parts):
                            if part in ["ascii", "utf8", "utf16", "utf32", "utf32le"]:
                                type_index = i
                                break

                        if type_index is not None and type_index + 1 < len(parts):
                            # Extract string content after the type indicator
                            string_content = " ".join(parts[type_index + 1 :])
                            if len(string_content) >= 4:  # Minimum length filter
                                strings.append(string_content)
            return strings
        except Exception as e:
            self.logger.debug(f"Failed to extract izz strings: {e}")
            return []

    def _analyze_strings_for_libraries(
        self, strings: list[str], binary_info: NativeBinaryInfo
    ) -> list[NativeLibraryDetection]:
        """Analyze strings to detect library versions."""
        detections = []

        for string in strings:
            # 1. Check for --prefix= patterns
            prefix_detections = self._detect_prefix_libraries(string, binary_info)
            detections.extend(prefix_detections)

            # 2. Check for direct version string patterns
            version_detections = self._detect_version_strings(string, binary_info)
            detections.extend(version_detections)

            # 3. Check for build information
            build_detections = self._detect_build_info(string, binary_info)
            detections.extend(build_detections)

        return detections

    def _detect_prefix_libraries(self, string: str, binary_info: NativeBinaryInfo) -> list[NativeLibraryDetection]:
        """Detect libraries from --prefix= compilation flags."""
        detections = []

        # Look for --prefix= pattern
        prefix_match = self.prefix_pattern.search(string)
        if not prefix_match:
            return detections

        prefix_path = prefix_match.group(1)

        # Analyze the prefix path for library-version patterns
        for library_name, patterns in self.library_path_patterns.items():
            for pattern in patterns:
                match = pattern.search(prefix_path)
                if match:
                    # Extract version information
                    if library_name == "FFmpeg":
                        # Special handling for FFmpeg version format
                        # lib_name = match.group(1)  # Not used after assignment
                        version_prefix = match.group(2) if len(match.groups()) >= 2 else ""
                        version = match.group(3) if len(match.groups()) >= 3 else match.group(2)

                        # Clean up version prefix (n, v, etc.)
                        if version_prefix.lower() in ["n", "v"]:
                            version = version_prefix + version

                    elif library_name == "x264":
                        # Special handling for x264
                        # lib_prefix = match.group(1) if match.group(1) else ''  # Not used after assignment
                        # lib_name = lib_prefix + match.group(2)  # Not used after assignment
                        version = match.group(3)
                        if version.lower() == "stable":
                            version = "stable"

                    else:
                        # Standard library-version pattern
                        # lib_name = match.group(1)  # Not used in standard pattern
                        version = match.group(2)

                    detection = NativeLibraryDetection(
                        library_name=library_name,
                        version=version,
                        confidence=0.8,  # High confidence for prefix patterns
                        source_type="prefix",
                        source_evidence=f"--prefix={prefix_path}",
                        file_path=str(binary_info.relative_path),
                        additional_info={
                            "full_prefix": prefix_path,
                            "matched_pattern": pattern.pattern,
                            "original_string": string[:200],  # Truncate for storage
                        },
                    )
                    detections.append(detection)
                    break  # Only take first match per library

        return detections

    def _detect_version_strings(self, string: str, binary_info: NativeBinaryInfo) -> list[NativeLibraryDetection]:
        """Detect libraries from direct version strings in binary content."""
        detections = []

        for library_name, patterns in self.version_string_patterns.items():
            for pattern in patterns:
                match = pattern.search(string)
                if match:
                    # Extract version information
                    if library_name == "FFmpeg" and len(match.groups()) >= 3:
                        # lib_name = match.group(1)  # Not used after assignment
                        version_prefix = match.group(2) if match.group(2) else ""
                        version = match.group(3)

                        # Clean up version prefix
                        if version_prefix.lower() in ["n", "v"]:
                            version = version_prefix + version
                    else:
                        # lib_name = match.group(1)  # Not used in this path
                        version = match.group(2)

                    detection = NativeLibraryDetection(
                        library_name=library_name,
                        version=version,
                        confidence=0.7,  # Good confidence for version strings
                        source_type="version_string",
                        source_evidence=string,
                        file_path=str(binary_info.relative_path),
                        additional_info={"matched_pattern": pattern.pattern, "full_string": string},
                    )
                    detections.append(detection)
                    break  # Only take first match per library

        return detections

    def _detect_build_info(self, string: str, binary_info: NativeBinaryInfo) -> list[NativeLibraryDetection]:
        """Detect version information from build flags and compilation info."""
        detections = []

        for pattern in self.build_info_patterns:
            match = pattern.search(string)
            if match:
                version = match.group(1)

                detection = NativeLibraryDetection(
                    library_name="unknown",  # Will be cross-referenced later
                    version=version,
                    confidence=0.4,  # Lower confidence for build info alone
                    source_type="build_info",
                    source_evidence=string,
                    file_path=str(binary_info.relative_path),
                    additional_info={"matched_pattern": pattern.pattern, "full_string": string},
                )
                detections.append(detection)

        return detections

    def _cross_reference_detections(self, detections: list[NativeLibraryDetection]) -> list[NativeLibraryDetection]:
        """Cross-reference detections to improve confidence and remove duplicates."""
        # Group detections by library name
        library_groups = {}
        build_info_detections = []

        for detection in detections:
            if detection.library_name == "unknown":
                build_info_detections.append(detection)
            else:
                if detection.library_name not in library_groups:
                    library_groups[detection.library_name] = []
                library_groups[detection.library_name].append(detection)

        final_detections = []

        # Process each library group
        for library_name, group_detections in library_groups.items():
            if len(group_detections) == 1:
                # Single detection - use as is
                final_detections.append(group_detections[0])
            else:
                # Multiple detections - merge and boost confidence
                best_detection = max(group_detections, key=lambda x: x.confidence)

                # Check if versions match across detections
                versions = [d.version for d in group_detections]
                if len(set(versions)) == 1:
                    # All versions match - boost confidence
                    best_detection.confidence = min(0.95, best_detection.confidence + 0.15)
                    best_detection.additional_info["cross_references"] = len(group_detections)
                    best_detection.additional_info["sources"] = [d.source_type for d in group_detections]

                final_detections.append(best_detection)

        # Apply confidence filter
        filtered_detections = [d for d in final_detections if d.confidence >= self.min_confidence]

        # Apply limit
        if len(filtered_detections) > self.max_libraries_per_binary:
            filtered_detections.sort(key=lambda x: x.confidence, reverse=True)
            filtered_detections = filtered_detections[: self.max_libraries_per_binary]

        return filtered_detections

    def get_module_name(self) -> str:
        """Get the module name."""
        return "native_library_version"

    def can_analyze(self, binary_info: NativeBinaryInfo) -> bool:
        """Check if this module can analyze the given binary."""
        # Only analyze .so files and only if enabled
        return (
            self.enabled and binary_info.file_name.endswith(".so") and binary_info.file_size > 1024
        )  # Skip very small files
