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
Native Binary Analysis Loader Module.

This module serves as the main orchestrator for native binary analysis using radare2.
It discovers native binaries in unzipped APKs, manages r2pipe connections, and
coordinates the execution of native analysis modules.
"""

import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Optional

try:
    import r2pipe
except ImportError:
    r2pipe = None

# Import core framework components
from ...core.base_classes import AnalysisContext
from ...core.base_classes import AnalysisStatus
from ...core.base_classes import BaseAnalysisModule
from ...core.base_classes import BaseResult
from ...core.base_classes import register_module

# Import native analysis components
from .base_native_module import BaseNativeModule
from .base_native_module import NativeAnalysisResult
from .base_native_module import NativeBinaryInfo
from .base_native_module import NativeStringSource


@dataclass
class NativeAnalysisModuleResult(BaseResult):
    """Result container for the native analysis loader module."""

    analyzed_binaries: list[NativeBinaryInfo] = None
    total_strings_extracted: int = 0
    strings_by_source: dict[str, list[NativeStringSource]] = None
    module_results: dict[str, list[NativeAnalysisResult]] = None
    analysis_errors: list[str] = None
    radare2_available: bool = False

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.analyzed_binaries is None:
            self.analyzed_binaries = []
        if self.strings_by_source is None:
            self.strings_by_source = {}
        if self.module_results is None:
            self.module_results = {}
        if self.analysis_errors is None:
            self.analysis_errors = []

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization."""
        base_dict = super().to_dict()
        base_dict.update(
            {
                "analyzed_binaries": [
                    {
                        "file_path": str(binary.file_path),
                        "relative_path": binary.relative_path,
                        "architecture": binary.architecture,
                        "file_size": binary.file_size,
                        "file_name": binary.file_name,
                    }
                    for binary in self.analyzed_binaries
                ],
                "total_strings_extracted": self.total_strings_extracted,
                "strings_by_source": {
                    source: [
                        {
                            "content": s.content,
                            "source_type": s.source_type,
                            "file_path": s.file_path,
                            "extraction_method": s.extraction_method,
                            "offset": s.offset,
                            "encoding": s.encoding,
                            "confidence": s.confidence,
                        }
                        for s in strings
                    ]
                    for source, strings in self.strings_by_source.items()
                },
                "analysis_errors": self.analysis_errors,
                "radare2_available": self.radare2_available,
                "binaries_analyzed_count": len(self.analyzed_binaries),
                "architectures_found": list(set(b.architecture for b in self.analyzed_binaries)),
            }
        )
        return base_dict


@register_module("native_analysis")
class NativeAnalysisLoader(BaseAnalysisModule):
    """
    Main native binary analysis module that orchestrates native analysis.

    This module:
    1. Checks if temporal analysis is enabled and APK is unzipped
    2. Discovers native binaries (.so files) in the unzipped APK
    3. Filters binaries by configured architectures
    4. Manages r2pipe connections to binaries
    5. Executes registered native analysis modules
    6. Collects and aggregates results
    7. Integrates native strings with existing string analysis
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize NativeAnalysisLoaderModule with configuration."""
        super().__init__(config)
        self.native_modules: list[BaseNativeModule] = []
        self._initialize_native_modules()

    def _initialize_native_modules(self):
        """Initialize and register native analysis modules."""
        try:
            # Import and register native modules
            from .library_version_detection import NativeLibraryVersionModule
            from .string_extraction import NativeStringExtractionModule
            from .strings_fallback_detection import StringsFallbackDetectionModule

            # Get native module configurations
            native_config = self.config.get("modules", {})

            # Initialize string extraction module
            if native_config.get("string_extraction", {}).get("enabled", True):
                string_module = NativeStringExtractionModule(
                    config=native_config.get("string_extraction", {}), logger=self.logger
                )
                if string_module.is_enabled():
                    self.native_modules.append(string_module)
                    self.logger.debug("Registered NativeStringExtractionModule")

            # Initialize library version detection module
            if native_config.get("library_version_detection", {}).get("enabled", True):
                # Try radare2-based detection first
                version_module = NativeLibraryVersionModule(
                    config=native_config.get("library_version_detection", {}), logger=self.logger
                )

                # Check if radare2 is available and r2pipe works
                r2_available = r2pipe is not None and self._check_radare2_availability()

                if r2_available and version_module.is_enabled():
                    self.native_modules.append(version_module)
                    self.logger.debug("Registered NativeLibraryVersionModule (radare2-based)")
                else:
                    # Fallback to strings-based detection
                    self.logger.info(
                        "radare2 not available, using strings-based fallback for library version detection"
                    )
                    fallback_module = StringsFallbackDetectionModule(
                        config=native_config.get("library_version_detection", {}), logger=self.logger
                    )
                    if fallback_module.is_enabled():
                        self.native_modules.append(fallback_module)
                        self.logger.debug("Registered StringsFallbackDetectionModule")

        except ImportError as e:
            self.logger.warning(f"Failed to import native analysis modules: {e}")
        except Exception as e:
            self.logger.error(f"Error initializing native modules: {e}")

    def analyze(self, apk_path: str, context: AnalysisContext) -> NativeAnalysisModuleResult:
        """
        Perform native binary analysis on the APK.

        Args:
            apk_path: Path to the APK file
            context: Analysis context with shared data

        Returns:
            NativeAnalysisModuleResult with analysis results
        """
        start_time = time.time()

        try:
            # Check if r2pipe is available
            if r2pipe is None:
                self.logger.warning("r2pipe not available - skipping native analysis")
                return NativeAnalysisModuleResult(
                    module_name="native_analysis",
                    status=AnalysisStatus.SKIPPED,
                    execution_time=time.time() - start_time,
                    error_message="r2pipe not available",
                    radare2_available=False,
                )

            # Check if radare2 binary is available
            if not self._check_radare2_availability():
                self.logger.warning("radare2 binary not available - skipping native analysis")
                return NativeAnalysisModuleResult(
                    module_name="native_analysis",
                    status=AnalysisStatus.SKIPPED,
                    execution_time=time.time() - start_time,
                    error_message="radare2 binary not available",
                    radare2_available=False,
                )

            # Check if temporal analysis is enabled and APK is unzipped
            if not context.temporal_paths:
                self.logger.info("Temporal analysis not enabled - skipping native analysis")
                return NativeAnalysisModuleResult(
                    module_name="native_analysis",
                    status=AnalysisStatus.SKIPPED,
                    execution_time=time.time() - start_time,
                    error_message="Temporal analysis required but not enabled",
                    radare2_available=True,
                )

            # Discover native binaries
            self.logger.info("Discovering native binaries in unzipped APK...")
            native_binaries = self._discover_native_binaries(context.temporal_paths.unzipped_dir)

            if not native_binaries:
                self.logger.info("No native binaries found in APK")
                return NativeAnalysisModuleResult(
                    module_name="native_analysis",
                    status=AnalysisStatus.SUCCESS,
                    execution_time=time.time() - start_time,
                    radare2_available=True,
                )

            self.logger.info(f"Found {len(native_binaries)} native binaries to analyze")

            # Filter binaries by architecture
            filtered_binaries = self._filter_binaries_by_architecture(native_binaries)
            self.logger.info(f"Analyzing {len(filtered_binaries)} binaries after architecture filtering")

            # Analyze binaries with native modules
            results = self._analyze_binaries(filtered_binaries)

            # Aggregate results and extract strings
            all_strings = []
            strings_by_source = {}
            analysis_errors = []
            detected_native_libraries = []

            for binary_results in results.values():
                for result in binary_results:
                    if result.strings_found:
                        all_strings.extend(result.strings_found)
                        source_key = result.binary_info.relative_path
                        strings_by_source[source_key] = result.strings_found

                    # Extract library version detection results
                    if (
                        result.module_name == "native_library_version"
                        and result.additional_data
                        and "detected_libraries" in result.additional_data
                    ):
                        detected_native_libraries.extend(result.additional_data["detected_libraries"])

                    if result.error_message:
                        analysis_errors.append(f"{result.binary_info.file_name}: {result.error_message}")

            # Integrate native strings with context for other modules to use
            if all_strings:
                self._integrate_native_strings(context, all_strings)
                self.logger.info(f"Extracted {len(all_strings)} strings from native binaries")

            # Integrate native library detections with context for library detection module
            if detected_native_libraries:
                self._integrate_native_libraries(context, detected_native_libraries)
                self.logger.info(f"Detected {len(detected_native_libraries)} native libraries with versions")

            return NativeAnalysisModuleResult(
                module_name="native_analysis",
                status=AnalysisStatus.SUCCESS,
                execution_time=time.time() - start_time,
                analyzed_binaries=filtered_binaries,
                total_strings_extracted=len(all_strings),
                strings_by_source=strings_by_source,
                module_results=results,
                analysis_errors=analysis_errors,
                radare2_available=True,
            )

        except Exception as e:
            self.logger.error(f"Native analysis failed: {str(e)}")
            return NativeAnalysisModuleResult(
                module_name="native_analysis",
                status=AnalysisStatus.FAILURE,
                execution_time=time.time() - start_time,
                error_message=str(e),
                radare2_available=r2pipe is not None,
            )

    def _check_radare2_availability(self) -> bool:
        """Check if radare2 binary is available."""
        try:
            # Get radare2 configuration
            from ...core.configuration import Configuration

            config = Configuration()
            radare2_config = config.get_tool_config("radare2")

            # First try configured path
            radare2_path = radare2_config.get("path")
            if radare2_path:
                if Path(radare2_path).exists():
                    return True
                else:
                    self.logger.debug(f"Configured radare2 path does not exist: {radare2_path}")

            # Try common radare2 command names in PATH
            for command in ["r2", "radare2"]:
                if shutil.which(command) is not None:
                    self.logger.debug(f"Found radare2 as '{command}' in PATH")
                    return True

            # Try fallback paths from configuration
            fallback_paths = radare2_config.get("fallback_paths", [])
            for fallback_path in fallback_paths:
                if Path(fallback_path).exists():
                    self.logger.debug(f"Found radare2 at fallback path: {fallback_path}")
                    return True

            self.logger.debug("radare2 not found in PATH or fallback paths")
            return False

        except Exception as e:
            self.logger.debug(f"Error checking radare2 availability: {e}")
            return False

    def _discover_native_binaries(self, unzipped_dir: Path) -> list[NativeBinaryInfo]:
        """
        Discover native binaries in the unzipped APK directory.

        Args:
            unzipped_dir: Path to unzipped APK directory

        Returns:
            List of discovered native binaries
        """
        binaries = []

        # Get file patterns from configuration
        file_patterns = self.config.get("file_patterns", ["*.so"])

        try:
            # Look for native libraries in lib/ directory
            lib_dir = unzipped_dir / "lib"
            if lib_dir.exists():
                for pattern in file_patterns:
                    for binary_file in lib_dir.rglob(pattern):
                        if binary_file.is_file():
                            # Extract architecture from path (e.g., lib/arm64-v8a/libexample.so)
                            path_parts = binary_file.relative_to(unzipped_dir).parts
                            architecture = "unknown"
                            if len(path_parts) >= 3 and path_parts[0] == "lib":
                                architecture = path_parts[1]  # e.g., "arm64-v8a"

                            binary_info = NativeBinaryInfo(
                                file_path=binary_file,
                                relative_path=str(binary_file.relative_to(unzipped_dir)),
                                architecture=architecture,
                                file_size=binary_file.stat().st_size,
                                file_name=binary_file.name,
                            )
                            binaries.append(binary_info)

        except Exception as e:
            self.logger.error(f"Error discovering native binaries: {e}")

        return binaries

    def _filter_binaries_by_architecture(self, binaries: list[NativeBinaryInfo]) -> list[NativeBinaryInfo]:
        """
        Filter binaries by configured architectures.

        Args:
            binaries: List of discovered binaries

        Returns:
            List of filtered binaries
        """
        allowed_architectures = self.config.get("architectures", ["arm64-v8a"])

        filtered = []
        for binary in binaries:
            if binary.architecture in allowed_architectures:
                filtered.append(binary)
            else:
                self.logger.debug(
                    f"Skipping {binary.file_name} - architecture {binary.architecture} not in allowed list"
                )

        return filtered

    def _analyze_binaries(self, binaries: list[NativeBinaryInfo]) -> dict[str, list[NativeAnalysisResult]]:
        """
        Analyze native binaries using registered native modules.

        Args:
            binaries: List of binaries to analyze

        Returns:
            Dictionary mapping module names to analysis results
        """
        results = {}

        # Get radare2 configuration
        from ...core.configuration import Configuration

        config = Configuration()
        radare2_config = config.get_tool_config("radare2")
        timeout = radare2_config.get("timeout", 120)

        for binary in binaries:
            self.logger.debug(f"Analyzing native binary: {binary.relative_path}")

            try:
                # Open r2pipe connection
                r2 = self._open_r2pipe_connection(binary.file_path, timeout)
                if r2 is None:
                    self.logger.warning(f"Failed to open r2pipe connection for {binary.file_name}")
                    continue

                # Run each native analysis module
                for module in self.native_modules:
                    if not module.can_analyze(binary):
                        continue

                    module_name = module.get_module_name()
                    if module_name not in results:
                        results[module_name] = []

                    try:
                        self.logger.debug(f"Running {module_name} on {binary.file_name}")
                        result = module.analyze_binary(binary, r2)
                        results[module_name].append(result)

                    except Exception as e:
                        self.logger.error(f"Module {module_name} failed on {binary.file_name}: {e}")
                        error_result = NativeAnalysisResult(
                            binary_info=binary, module_name=module_name, success=False, error_message=str(e)
                        )
                        results[module_name].append(error_result)

                # Close r2pipe connection
                try:
                    r2.quit()
                except Exception:
                    # Ignore r2pipe cleanup errors
                    pass

            except Exception as e:
                self.logger.error(f"Error analyzing binary {binary.file_name}: {e}")

        return results

    def _open_r2pipe_connection(self, binary_path: Path, timeout: int) -> Optional[Any]:
        """
        Open an r2pipe connection to a native binary.

        Args:
            binary_path: Path to the native binary
            timeout: Connection timeout

        Returns:
            r2pipe connection or None if failed
        """
        import os

        try:
            # Get radare2 configuration
            from ...core.configuration import Configuration

            config = Configuration()
            radare2_config = config.get_tool_config("radare2")

            radare2_path = radare2_config.get("path")
            options = radare2_config.get("options", [])

            # If no configured path, try to find radare2
            if not radare2_path:
                # Try common command names
                for command in ["r2", "radare2"]:
                    if shutil.which(command):
                        radare2_path = command
                        self.logger.debug(f"Using radare2 command: {command}")
                        break

                # If still not found, try fallback paths
                if not radare2_path:
                    fallback_paths = radare2_config.get("fallback_paths", [])
                    for fallback_path in fallback_paths:
                        if Path(fallback_path).exists():
                            radare2_path = fallback_path
                            self.logger.debug(f"Using radare2 from fallback path: {fallback_path}")
                            break

            if not radare2_path:
                self.logger.warning("No radare2 binary found")
                return None

            # Ensure radare2 is accessible to r2pipe by modifying PATH if needed
            old_path = os.environ.get("PATH", "")
            path_modified = False

            if not shutil.which("r2") and not shutil.which("radare2"):
                # Add the directory containing radare2 to PATH
                radare2_dir = Path(radare2_path).parent
                os.environ["PATH"] = f"{radare2_dir}:{old_path}"
                path_modified = True
                self.logger.debug(f"Added {radare2_dir} to PATH for r2pipe")

            try:
                # Open connection with timeout handling
                r2 = r2pipe.open(str(binary_path), flags=options)

                # Basic initialization (skip auto-analysis for performance)
                # r2.cmd("aaa")  # Auto-analyze all - commented out for speed

                return r2

            finally:
                # Restore original PATH if we modified it
                if path_modified:
                    os.environ["PATH"] = old_path

        except Exception as e:
            self.logger.debug(f"Failed to open r2pipe connection to {binary_path}: {e}")
            return None

    def _integrate_native_strings(self, context: AnalysisContext, native_strings: list[NativeStringSource]):
        """
        Integrate native strings with the analysis context for other modules to use.

        Args:
            context: Analysis context
            native_strings: List of strings extracted from native binaries
        """
        try:
            # Add native strings to context for other modules
            if "native_strings" not in context.module_results:
                context.module_results["native_strings"] = []

            # Convert to format expected by string analysis modules
            string_contents = [s.content for s in native_strings]
            context.module_results["native_strings"].extend(string_contents)

            # Also store detailed native string information
            context.module_results["native_string_sources"] = native_strings

            self.logger.debug(f"Added {len(native_strings)} native strings to analysis context")

        except Exception as e:
            self.logger.error(f"Error integrating native strings: {e}")

    def _integrate_native_libraries(self, context: AnalysisContext, detected_native_libraries: list[dict[str, Any]]):
        """
        Integrate native library detections with the analysis context for library detection module.

        Args:
            context: Analysis context
            detected_native_libraries: List of detected native libraries with version information
        """
        try:
            # Add native library detections to context for library detection module
            if "native_libraries" not in context.module_results:
                context.module_results["native_libraries"] = []

            # Convert native library detections to format expected by library detection system
            for native_lib in detected_native_libraries:
                # Create standardized library detection format
                library_detection = {
                    "name": native_lib.get("library_name", ""),
                    "version": native_lib.get("version", ""),
                    "confidence": native_lib.get("confidence", 0.0),
                    "category": "native",
                    "detection_method": f"native_{native_lib.get('source_type', 'unknown')}",
                    "source_evidence": native_lib.get("source_evidence", ""),
                    "file_path": native_lib.get("file_path", ""),
                    "additional_info": {
                        "source_type": native_lib.get("source_type", ""),
                        "architecture": self._extract_architecture_from_path(native_lib.get("file_path", "")),
                        "native_detection": True,
                        **native_lib.get("additional_info", {}),
                    },
                }

                context.module_results["native_libraries"].append(library_detection)

                self.logger.debug(
                    f"Integrated native library: {native_lib.get('library_name')} {native_lib.get('version')} "
                    f"(confidence: {native_lib.get('confidence', 0.0):.2f})"
                )

            # Store count for statistics
            context.module_results["native_libraries_count"] = len(detected_native_libraries)

            self.logger.info(
                f"Successfully integrated {len(detected_native_libraries)} native libraries into analysis context"
            )

        except Exception as e:
            self.logger.error(f"Error integrating native libraries: {e}")

    def _extract_architecture_from_path(self, file_path: str) -> str:
        """Extract architecture from native library file path."""
        try:
            # Common Android architectures in lib paths
            architectures = ["arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64", "mips", "mips64"]

            for arch in architectures:
                if arch in file_path:
                    return arch

            return "unknown"

        except Exception:
            return "unknown"

    def get_dependencies(self) -> list[str]:
        """Get list of module dependencies."""
        # Native analysis should run after basic analysis is done
        return ["apk_overview", "string_analysis"]
