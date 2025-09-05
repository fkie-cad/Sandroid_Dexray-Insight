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
Strings-based Fallback Native Library Version Detection.

This module provides a fallback method for detecting library versions from native
binaries when radare2 is not available, using the standard `strings` command.
"""

import shutil
import subprocess
import time
from typing import Any
from typing import Optional

from .base_native_module import BaseNativeModule
from .base_native_module import NativeAnalysisResult
from .base_native_module import NativeBinaryInfo
from .library_version_detection import NativeLibraryDetection


class StringsFallbackDetectionModule(BaseNativeModule):
    """
    Fallback native library version detection using the `strings` command.

    This module uses the standard Unix `strings` utility to extract readable
    strings from native binaries and applies the same pattern matching logic
    as the radare2-based detection.
    """

    def __init__(self, config: dict[str, Any], logger: Optional[Any] = None):
        """Initialize StringsFallbackDetectionModule with configuration."""
        super().__init__(config, logger)

        # Configuration
        self.enabled = config.get("enabled", True)
        self.min_confidence = config.get("min_confidence", 0.6)
        self.max_libraries_per_binary = config.get("max_libraries_per_binary", 10)
        self.strings_timeout = config.get("strings_timeout", 30)  # Timeout for strings command

        # Import detection patterns from the main detection module
        self._initialize_patterns()

        # Check if strings command is available
        self.strings_available = shutil.which("strings") is not None
        if not self.strings_available:
            self.logger.warning("strings command not available - strings fallback detection disabled")

    def _initialize_patterns(self):
        """Initialize detection patterns from the main detection module."""
        from .library_version_detection import NativeLibraryVersionModule

        # Create a temporary instance to get patterns
        temp_module = NativeLibraryVersionModule({}, self.logger)

        # Copy patterns
        self.prefix_pattern = temp_module.prefix_pattern
        self.library_path_patterns = temp_module.library_path_patterns
        self.version_string_patterns = temp_module.version_string_patterns
        self.build_info_patterns = temp_module.build_info_patterns

    def analyze_binary(self, binary_info: NativeBinaryInfo, r2: Any = None) -> NativeAnalysisResult:
        """
        Analyze a native binary using strings command fallback.

        Args:
            binary_info: Information about the binary being analyzed
            r2: Unused in this fallback implementation

        Returns:
            NativeAnalysisResult with detected library versions
        """
        start_time = time.time()

        try:
            if not self.strings_available:
                return NativeAnalysisResult(
                    binary_info=binary_info,
                    module_name=self.get_module_name(),
                    success=False,
                    error_message="strings command not available",
                    execution_time=time.time() - start_time,
                )

            self.logger.debug(f"Using strings fallback for {binary_info.file_name}")

            # Extract strings using the strings command
            extracted_strings = self._extract_strings_with_command(binary_info)

            if not extracted_strings:
                self.logger.debug(f"No strings extracted from {binary_info.file_name}")
                return NativeAnalysisResult(
                    binary_info=binary_info,
                    module_name=self.get_module_name(),
                    success=True,
                    execution_time=time.time() - start_time,
                    additional_data={"detected_libraries": [], "total_detections": 0, "method": "strings_fallback"},
                )

            # Analyze strings for library version patterns
            detected_libraries = self._analyze_strings_for_libraries(extracted_strings, binary_info)

            # Cross-reference and build confidence scores
            final_detections = self._cross_reference_detections(detected_libraries)

            self.logger.debug(
                f"Strings fallback found {len(final_detections)} library versions in {binary_info.file_name}"
            )

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
                            "additional_info": {**lib.additional_info, "detection_method": "strings_fallback"},
                        }
                        for lib in final_detections
                    ],
                    "total_detections": len(final_detections),
                    "method": "strings_fallback",
                    "strings_extracted": len(extracted_strings),
                },
            )

        except Exception as e:
            self.logger.error(f"Strings fallback analysis failed for {binary_info.file_name}: {e}")
            return NativeAnalysisResult(
                binary_info=binary_info,
                module_name=self.get_module_name(),
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )

    def _extract_strings_with_command(self, binary_info: NativeBinaryInfo) -> list[str]:
        """Extract strings from binary using the strings command."""
        try:
            # Run strings command with options for better extraction
            cmd = [
                "strings",
                "-n",
                "4",  # Minimum string length of 4
                "-a",  # Scan entire file
                str(binary_info.file_path),
            ]

            self.logger.debug(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.strings_timeout,
                encoding="utf-8",
                errors="ignore",  # Ignore encoding errors
            )

            if result.returncode != 0:
                self.logger.warning(f"strings command failed for {binary_info.file_name}: {result.stderr}")
                return []

            # Split output into lines and filter
            strings = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if len(line) >= 4:  # Minimum length filter
                    strings.append(line)

            self.logger.debug(f"Extracted {len(strings)} strings from {binary_info.file_name}")
            return strings

        except subprocess.TimeoutExpired:
            self.logger.warning(f"strings command timed out for {binary_info.file_name}")
            return []
        except Exception as e:
            self.logger.warning(f"Error running strings command for {binary_info.file_name}: {e}")
            return []

    def _analyze_strings_for_libraries(
        self, strings: list[str], binary_info: NativeBinaryInfo
    ) -> list[NativeLibraryDetection]:
        """Analyze strings to detect library versions - reuses patterns from main module."""
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
        """Detect libraries from --prefix= compilation flags - reuses logic from main module."""
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
                    # Extract version information (same logic as main module)
                    if library_name == "FFmpeg":
                        # Special handling for FFmpeg version format
                        version_prefix = match.group(2) if len(match.groups()) >= 2 else ""
                        version = match.group(3) if len(match.groups()) >= 3 else match.group(2)

                        # Clean up version prefix (n, v, etc.)
                        if version_prefix.lower() in ["n", "v"]:
                            version = version_prefix + version

                    elif library_name == "x264":
                        # Special handling for x264
                        version = match.group(3)
                        if version.lower() == "stable":
                            version = "stable"

                    else:
                        # Standard library-version pattern
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
                            "detection_method": "strings_fallback",
                        },
                    )
                    detections.append(detection)
                    break  # Only take first match per library

        return detections

    def _detect_version_strings(self, string: str, binary_info: NativeBinaryInfo) -> list[NativeLibraryDetection]:
        """Detect libraries from direct version strings - reuses logic from main module."""
        detections = []

        for library_name, patterns in self.version_string_patterns.items():
            for pattern in patterns:
                match = pattern.search(string)
                if match:
                    # Extract version information (same logic as main module)
                    if library_name == "FFmpeg" and len(match.groups()) >= 3:
                        version_prefix = match.group(2) if match.group(2) else ""
                        version = match.group(3)

                        # Clean up version prefix
                        if version_prefix.lower() in ["n", "v"]:
                            version = version_prefix + version
                    else:
                        version = match.group(2)

                    detection = NativeLibraryDetection(
                        library_name=library_name,
                        version=version,
                        confidence=0.7,  # Good confidence for version strings
                        source_type="version_string",
                        source_evidence=string,
                        file_path=str(binary_info.relative_path),
                        additional_info={
                            "matched_pattern": pattern.pattern,
                            "full_string": string,
                            "detection_method": "strings_fallback",
                        },
                    )
                    detections.append(detection)
                    break  # Only take first match per library

        return detections

    def _detect_build_info(self, string: str, binary_info: NativeBinaryInfo) -> list[NativeLibraryDetection]:
        """Detect version information from build flags - reuses logic from main module."""
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
                    additional_info={
                        "matched_pattern": pattern.pattern,
                        "full_string": string,
                        "detection_method": "strings_fallback",
                    },
                )
                detections.append(detection)

        return detections

    def _cross_reference_detections(self, detections: list[NativeLibraryDetection]) -> list[NativeLibraryDetection]:
        """Cross-reference detections - reuses logic from main module."""
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
        return "native_library_version_strings_fallback"

    def can_analyze(self, binary_info: NativeBinaryInfo) -> bool:
        """Check if this module can analyze the given binary."""
        return (
            self.enabled
            and self.strings_available
            and binary_info.file_name.endswith(".so")
            and binary_info.file_size > 1024
        )  # Skip very small files
