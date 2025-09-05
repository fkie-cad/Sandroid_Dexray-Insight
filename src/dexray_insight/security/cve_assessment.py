#!/usr/bin/env python3

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
CVE (Common Vulnerabilities and Exposures) Assessment.

This module provides comprehensive CVE vulnerability scanning for detected libraries
by querying multiple online CVE databases including OSV, NVD, and GitHub Advisory.
"""

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from pathlib import Path
from typing import Any

from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment
from .cve.clients.github_client import GitHubAdvisoryClient
from .cve.clients.nvd_client import NVDClient
from .cve.clients.osv_client import OSVClient
from .cve.models.vulnerability import CVESeverity
from .cve.models.vulnerability import CVEVulnerability
from .cve.utils.cache_manager import CVECacheManager


@register_assessment("cve_scanning")
class CVEAssessment(BaseSecurityAssessment):
    """CVE vulnerability scanning assessment using online databases.

    This assessment scans detected libraries with identified versions against
    multiple CVE databases to identify known security vulnerabilities.

    Supported CVE sources:
    - OSV (Open Source Vulnerabilities) - Google's vulnerability database
    - NVD (National Vulnerability Database) - NIST's vulnerability database
    - GitHub Advisory Database - GitHub's security advisory database

    Features:
    - Rate limiting to respect API limits
    - Caching to avoid repeated queries
    - Parallel scanning for performance
    - Severity-based finding classification
    - Comprehensive remediation guidance
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize CVE assessment with configuration.

        Args:
            config: CVE scanning configuration dictionary.
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "CVE Vulnerability Scanning"

        # Get security configuration - handle both assessment config and full security config
        security_config = config if "cve_scanning" in config else config.get("security", {})

        # CVE scanning configuration
        cve_config = security_config.get("cve_scanning", {})

        # Check if CVE scanning is enabled
        if not cve_config.get("enabled", False):
            self.logger.info("CVE scanning is disabled in configuration")
            self.sources_config = {}
            self.scan_config = {}
            self.cache_manager = None
            self.clients = {}
            return

        # CVE data sources configuration - respect config defaults
        sources_config = cve_config.get("sources", {})
        self.sources_config = self.build_sources_config(sources_config)
        # self.sources_config = {
        #    'osv': {
        #        'enabled': sources_config.get('osv', {}).get('enabled', False),  # Default False to respect config
        #        'api_key': sources_config.get('osv', {}).get('api_key')
        #    },
        #    'nvd': {
        #        'enabled': sources_config.get('nvd', {}).get('enabled', False),  # Default False to respect config
        #        'api_key': sources_config.get('nvd', {}).get('api_key')
        #    },
        #    'github': {
        #        'enabled': sources_config.get('github', {}).get('enabled', False),  # Default False to respect config
        #        'api_key': sources_config.get('github', {}).get('api_key')
        #    }
        # }

        # Scanning configuration with more conservative defaults to avoid rate limiting
        self.scan_config = {
            "max_workers": cve_config.get("max_workers", 2),  # Reduced from 3 to avoid overwhelming APIs
            "timeout_seconds": cve_config.get("timeout_seconds", 30),
            "overall_timeout_minutes": cve_config.get("overall_timeout_minutes", 10),  # Total scan timeout
            "min_confidence": cve_config.get("min_confidence", 0.7),
            "cache_duration_hours": cve_config.get("cache_duration_hours", 24),
            "max_libraries_per_source": cve_config.get("max_libraries_per_source", 30),  # Reduced from 50
            "retry_attempts": cve_config.get("retry_attempts", 2),
            "retry_delay_seconds": cve_config.get("retry_delay_seconds", 5),
            # Library type filtering configuration
            "scan_native_only": cve_config.get("scan_native_only", True),  # Default to native only
            "include_java_libraries": cve_config.get("include_java_libraries", False),
            "native_library_patterns": cve_config.get(
                "native_library_patterns",
                [
                    "*.so",
                    "*ffmpeg*",
                    "*openssl*",
                    "*curl*",
                    "*sqlite*",
                    "*crypto*",
                    "*ssl*",
                    "*zlib*",
                    "*png*",
                    "*jpeg*",
                    "*webp*",
                ],
            ),
        }

        # Initialize cache manager
        cache_dir_config = cve_config.get("cache_dir")
        cache_dir = Path(cache_dir_config) if cache_dir_config else Path.home() / ".dexray_insight" / "cve_cache"

        self.cache_manager = CVECacheManager(
            cache_dir=cache_dir, cache_duration_hours=self.scan_config["cache_duration_hours"]
        )

        # Initialize CVE clients
        self.clients = {}
        self._initialize_clients()

        # Threading lock for thread-safe operations
        self._lock = threading.Lock()

        # Vulnerability aggregation
        self.found_vulnerabilities = []

    def _normalize_api_key(self, value: str | None, placeholders: set[str] | None = None) -> str | None:
        """Return None if value is empty or a placeholder; otherwise return trimmed string."""
        if value is None:
            return None
        if placeholders is None:
            placeholders = set()
        s = str(value).strip().strip('"').strip("'")
        if not s:
            return None
        if s in placeholders:
            return None
        su = s.upper()
        if su.startswith("YOUR_") or su in {"NONE", "NULL", "<NONE>", "<NULL>"}:
            return None
        return s

    def build_sources_config(self, sources_config: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Build and validate CVE sources configuration."""
        defaults = {
            "osv": {"enabled": False, "api_key": None},
            "nvd": {"enabled": False, "api_key": None},
            "github": {"enabled": False, "api_key": None},
        }

        # Platzhalter, die wir explizit als "nicht gesetzt" werten
        placeholders = {
            "osv": {"YOUR_OSV_API_KEY"},
            "nvd": {"YOUR_NVD_API_KEY"},
            "github": {"YOUR_GITHUB_TOKEN", "YOUR_GITHUB_API_KEY"},
        }

        # Env-Fallbacks
        env_vars = {"osv": "OSV_API_KEY", "nvd": "NVD_API_KEY", "github": "GITHUB_TOKEN"}

        out: dict[str, dict[str, Any]] = {}

        for name, dflt in defaults.items():
            src = (sources_config or {}).get(name) or {}
            enabled = bool(src.get("enabled", dflt["enabled"]))

            api_key = self._normalize_api_key(src.get("api_key"), placeholders.get(name, set()))
            if api_key is None:
                api_key = self._normalize_api_key(os.getenv(env_vars[name]))

            out[name] = {"enabled": enabled, "api_key": api_key}

        return out

    def _initialize_clients(self):
        """Initialize CVE database clients based on configuration."""
        self.logger.info("=== CVE Client Initialization ===")
        self.logger.info(f"Sources configuration: {self.sources_config}")

        # OSV Client - respect configuration setting
        osv_enabled = self.sources_config.get("osv", {}).get("enabled", False)  # Default False to respect config
        self.logger.info(f"OSV enabled in config: {osv_enabled}")
        if osv_enabled:
            try:
                self.clients["osv"] = OSVClient(
                    api_key=self.sources_config.get("osv", {}).get("api_key"),
                    timeout=self.scan_config["timeout_seconds"],
                    cache_manager=self.cache_manager,
                )
                self.logger.info("✅ OSV client initialized successfully (enabled in config)")
            except Exception as e:
                self.logger.warning(f"❌ Failed to initialize OSV client: {e}")
        else:
            self.logger.info("⏭️  OSV client skipped (disabled in configuration)")

        # NVD Client - respect configuration setting
        nvd_enabled = self.sources_config.get("nvd", {}).get("enabled", False)  # Default False to respect config
        self.logger.info(f"NVD enabled in config: {nvd_enabled}")
        if nvd_enabled:
            try:
                self.clients["nvd"] = NVDClient(
                    api_key=self.sources_config.get("nvd", {}).get("api_key"),
                    timeout=self.scan_config["timeout_seconds"],
                    cache_manager=self.cache_manager,
                )
                self.logger.info("✅ NVD client initialized successfully (enabled in config)")
            except Exception as e:
                self.logger.warning(f"❌ Failed to initialize NVD client: {e}")
        else:
            self.logger.info("⏭️  NVD client skipped (disabled in configuration)")

        # GitHub Client - respect configuration setting
        github_enabled = self.sources_config.get("github", {}).get("enabled", False)  # Default False to respect config
        self.logger.info(f"GitHub enabled in config: {github_enabled}")
        if github_enabled:
            try:
                self.clients["github"] = GitHubAdvisoryClient(
                    api_key=self.sources_config.get("github", {}).get("api_key"),
                    timeout=self.scan_config["timeout_seconds"],
                    cache_manager=self.cache_manager,
                )
                self.logger.info("✅ GitHub Advisory client initialized successfully (enabled in config)")
            except Exception as e:
                self.logger.warning(f"❌ Failed to initialize GitHub Advisory client: {e}")
        else:
            self.logger.info("⏭️  GitHub Advisory client skipped (disabled in configuration)")

        # Summary of initialized clients
        self.logger.info("=== CVE Client Initialization Complete ===")
        self.logger.info(f"Total clients initialized: {len(self.clients)}")
        self.logger.info(f"Active client sources: {list(self.clients.keys())}")

        if not self.clients:
            self.logger.warning("⚠️  No CVE clients were successfully initialized")

    def assess(self, analysis_results: dict[str, Any], context: Any | None = None) -> list[SecurityFinding]:
        """
        Perform CVE vulnerability assessment on detected libraries with file location tracking.

        Args:
            analysis_results: Combined results from all analysis modules
            context: Analysis context for file location creation (optional for backward compatibility)

        Returns:
            List of security findings related to CVE vulnerabilities with precise file locations
        """
        findings = []

        try:
            # Check if CVE scanning is enabled
            if not hasattr(self, "clients") or not self.clients:
                self.logger.debug("CVE scanning is disabled or no clients available")
                return findings

            # Extract libraries with versions for scanning
            scannable_libraries = self._extract_scannable_libraries(analysis_results)

            if not scannable_libraries:
                self.logger.warning("No libraries with versions found for CVE scanning")
                # Provide diagnostic information
                library_results = analysis_results.get("library_detection", {})
                if hasattr(library_results, "export_to_dict"):
                    library_data = library_results.export_to_dict()
                elif hasattr(library_results, "to_dict"):
                    library_data = library_results.to_dict()
                else:
                    library_data = library_results

                all_libs = library_data.get("detected_libraries", []) if isinstance(library_data, dict) else []
                if all_libs:
                    with_versions = sum(1 for lib in all_libs if isinstance(lib, dict) and lib.get("version"))
                    high_confidence = sum(
                        1
                        for lib in all_libs
                        if isinstance(lib, dict) and lib.get("confidence", 0) >= self.scan_config["min_confidence"]
                    )
                    self.logger.warning(
                        f"CVE Scanner: {len(all_libs)} total libraries detected, {with_versions} with versions, {high_confidence} with sufficient confidence"
                    )
                else:
                    self.logger.warning("CVE Scanner: No libraries detected by library_detection module")
                return findings

            self.logger.info(f"Starting CVE scan for {len(scannable_libraries)} libraries")

            # Show which clients will be used
            enabled_clients = list(self.clients.keys())
            self.logger.info(f"CVE Scanner: Active clients: {enabled_clients}")
            if not enabled_clients:
                self.logger.error("CVE Scanner: No CVE clients are enabled! Check your configuration.")
                self.logger.error(
                    "CVE Scanner: Make sure to set 'enabled: true' for at least one source in dexray.yaml under security.cve_scanning.sources"
                )
                return findings

            # Perform CVE scanning
            raw_vulnerabilities = self._scan_libraries_for_cves(scannable_libraries)

            if raw_vulnerabilities:
                self.logger.info(f"Found {len(raw_vulnerabilities)} raw CVE vulnerabilities")

                # CRITICAL: Filter out irrelevant CVEs to prevent false positives
                filtered_vulnerabilities = self._filter_relevant_cves(raw_vulnerabilities, scannable_libraries)
                self.logger.info(
                    f"After relevance filtering: {len(filtered_vulnerabilities)} relevant CVE vulnerabilities"
                )

                if filtered_vulnerabilities:
                    # Create security findings from filtered vulnerabilities with file locations
                    findings = self._create_security_findings(filtered_vulnerabilities, scannable_libraries, context)
                else:
                    self.logger.info("No relevant CVE vulnerabilities found after filtering")
            else:
                self.logger.info("No CVE vulnerabilities found")

                # Create informational finding about successful scan
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.LOW,
                        title="CVE Vulnerability Scan Completed",
                        description=f"Successfully scanned {len(scannable_libraries)} libraries against CVE databases. No known vulnerabilities found.",
                        evidence=[
                            f"Scanned library: {lib['name']} {lib['version']}" for lib in scannable_libraries[:10]
                        ],
                        recommendations=[
                            "Continue monitoring libraries for new vulnerabilities",
                            "Keep libraries updated to latest versions",
                            "Consider automated dependency scanning in CI/CD",
                            "Subscribe to security advisories for critical libraries",
                        ],
                    )
                )

        except Exception as e:
            self.logger.error(f"CVE assessment failed: {str(e)}")

            # Create error finding
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title="CVE Scanning Error",
                    description=f"CVE vulnerability scanning encountered an error: {str(e)}",
                    evidence=[f"Error details: {str(e)}"],
                    recommendations=[
                        "Check CVE scanning configuration",
                        "Verify API keys and network connectivity",
                        "Review CVE scanning logs for details",
                        "Consider manual vulnerability assessment",
                    ],
                )
            )

        return findings

    def _extract_scannable_libraries(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract libraries with versions that can be scanned for CVEs (native and/or regular libraries based on config)."""
        scannable_libraries = []

        # Check configuration to determine what types of libraries to scan
        scan_native_only = self.scan_config.get("scan_native_only", True)
        include_java_libraries = self.scan_config.get("include_java_libraries", False)

        self.logger.debug(
            f"CVE Scanner: scan_native_only={scan_native_only}, include_java_libraries={include_java_libraries}"
        )

        # Extract regular Java/Android libraries from library_detection if configured to do so
        if not scan_native_only or include_java_libraries:
            library_results = analysis_results.get("library_detection", {})
            if hasattr(library_results, "export_to_dict"):
                library_data = library_results.export_to_dict()
            elif hasattr(library_results, "to_dict"):
                library_data = library_results.to_dict()
            else:
                library_data = library_results

            detected_regular_libs = library_data.get("detected_libraries", []) if isinstance(library_data, dict) else []
            self.logger.info(
                f"CVE Scanner: Found {len(detected_regular_libs)} regular libraries from library_detection"
            )

            # Add regular libraries to scannable list
            for library in detected_regular_libs:
                if isinstance(library, dict):
                    library_name = library.get("library_name", library.get("name", ""))
                    library_version = library.get("version", "")
                    confidence = library.get("confidence", 1.0)

                    if library_name and library_version:
                        scannable_libraries.append(
                            {
                                "name": library_name,
                                "version": library_version,
                                "confidence": confidence,
                                "detection_method": "library_detection",
                                "source": "library_detection",
                                "file_path": "",
                                "category": "java_library",
                            }
                        )
                        self.logger.debug(
                            f"CVE Scanner: Added regular library: {library_name} v{library_version} (confidence: {confidence:.2f})"
                        )

        # CRITICAL FIX: Get native libraries from analysis context where they're actually stored
        # Native libraries are integrated into the context during native analysis
        context = analysis_results.get("_analysis_context", {})

        # Try to get native libraries from context
        detected_native_libs = []
        if hasattr(context, "module_results") and "native_libraries" in context.module_results:
            detected_native_libs = context.module_results["native_libraries"]
            self.logger.debug(f"CVE Scanner: Found {len(detected_native_libs)} native libraries in analysis context")
        else:
            # Fallback: try to extract from native analysis module directly
            native_results = analysis_results.get("native_analysis", {})
            self.logger.debug(f"CVE Scanner: Native analysis results type: {type(native_results)}")

            # Check if native analysis has module results with detected libraries
            if hasattr(native_results, "module_results"):
                for module_name, module_results in native_results.module_results.items():
                    for result in module_results:
                        if (
                            hasattr(result, "additional_data")
                            and result.additional_data
                            and "detected_libraries" in result.additional_data
                        ):
                            extracted_libs = result.additional_data["detected_libraries"]
                            detected_native_libs.extend(extracted_libs)

                            # Enhanced debug logging to show which specific libraries are extracted
                            self.logger.debug(
                                f"CVE Scanner: Extracted {len(extracted_libs)} libraries from {module_name}:"
                            )
                            for lib in extracted_libs:
                                lib_name = lib.get("name", lib.get("library_name", "Unknown"))
                                lib_version = lib.get("version", "No version")
                                lib_path = lib.get("path", lib.get("file_path", "No path"))
                                confidence = lib.get("confidence", 0.0)
                                self.logger.debug(
                                    f"  - {lib_name} v{lib_version} (confidence: {confidence:.2f}) at {lib_path}"
                                )

        self.logger.info(f"CVE Scanner: Found {len(detected_native_libs)} native libraries for CVE scanning evaluation")

        # DEBUG: Print all detected native libraries with versions for troubleshooting
        if detected_native_libs:
            self.logger.debug("=== ALL DETECTED NATIVE LIBRARIES WITH VERSIONS ===")
            for i, lib in enumerate(detected_native_libs):
                lib_name = lib.get("name", lib.get("library_name", "Unknown"))
                lib_version = lib.get("version", "No version")
                lib_path = lib.get("path", lib.get("file_path", "No path"))
                confidence = lib.get("confidence", 0.0)
                self.logger.debug(f"  {i+1}. {lib_name} v{lib_version} (confidence: {confidence:.2f}) at {lib_path}")
            self.logger.debug("=== END NATIVE LIBRARIES LIST ===")
        else:
            self.logger.warning("CVE Scanner: No native libraries found - checking fallback locations...")
            # Additional debugging for troubleshooting
            if context:
                self.logger.debug(f"Context type: {type(context)}")
                if hasattr(context, "module_results"):
                    self.logger.debug(f"Context module_results keys: {list(context.module_results.keys())}")
                else:
                    self.logger.debug("Context has no module_results attribute")
            else:
                self.logger.debug("No analysis context found in results")

        # Group libraries by name and select highest confidence version (as requested)
        library_groups = {}

        for library in detected_native_libs:
            if isinstance(library, dict):
                library_name = library.get("name", library.get("library_name", ""))
                library_version = library.get("version", "")
                library_path = library.get("path", library.get("file_path", ""))
                confidence = library.get("confidence", 1.0)
                detection_method = library.get("detection_method", "native_analysis")

                # Skip libraries without essential information
                if not library_name or not library_version:
                    self.logger.debug(
                        f"CVE Scanner: Skipping library - missing name or version (name: {library_name}, version: {library_version})"
                    )
                    continue

                # Group by library name to handle duplicates
                if library_name not in library_groups:
                    library_groups[library_name] = []

                library_groups[library_name].append(
                    {
                        "name": library_name,
                        "version": library_version,
                        "confidence": confidence,
                        "detection_method": detection_method,
                        "source": "native_analysis",
                        "file_path": library_path,
                        "category": "native_library",
                    }
                )

        # Select highest confidence version for each library and prepare for CVE scanning
        scannable_libraries_count = 0
        native_libs_with_versions = len([lib for lib in detected_native_libs if lib.get("version")])

        for library_name, library_versions in library_groups.items():
            # Sort by confidence (highest first) as requested by user
            library_versions.sort(key=lambda x: x["confidence"], reverse=True)
            best_version = library_versions[0]

            # Log all versions found and which one was selected
            if len(library_versions) > 1:
                self.logger.debug(f"CVE Scanner: Found {len(library_versions)} versions for {library_name}:")
                for lib in library_versions:
                    marker = "✓ SELECTED" if lib == best_version else ""
                    self.logger.debug(
                        f"  - {lib['name']} v{lib['version']} (confidence: {lib['confidence']:.2f}) {marker}"
                    )

            # Only scan libraries with sufficient confidence
            if best_version["confidence"] >= self.scan_config.get("min_confidence", 0.7):
                # Build absolute path if not already absolute
                library_path = best_version["file_path"]
                if library_path and not library_path.startswith("/"):
                    temporal_dir = self._get_temporal_directory(analysis_results)
                    if temporal_dir:
                        library_path = f"{temporal_dir}/unzipped/{library_path}"
                    best_version["file_path"] = library_path

                # Group all .so files for this library (as requested by user)
                all_so_files = []
                for lib_version in library_versions:
                    if lib_version.get("file_path") and lib_version["file_path"].endswith(".so"):
                        all_so_files.append(lib_version["file_path"])

                best_version["all_so_files"] = all_so_files  # Store all related .so files
                scannable_libraries.append(best_version)
                scannable_libraries_count += 1

                self.logger.info(
                    f"CVE Scanner: Added native library: {best_version['name']} v{best_version['version']} (confidence: {best_version['confidence']:.2f}) with {len(all_so_files)} .so files"
                )
            else:
                self.logger.debug(
                    f"CVE Scanner: Skipped {library_name} - low confidence: {best_version['confidence']:.2f} < {self.scan_config.get('min_confidence', 0.7)}"
                )

        # Debug logging for native library filtering
        self.logger.info(f"CVE Scanner: Native libraries with versions: {native_libs_with_versions}")
        self.logger.info(f"CVE Scanner: Native libraries passed filtering: {scannable_libraries_count}")

        # Log all scannable libraries with their .so file paths
        for lib in scannable_libraries:
            self.logger.info(f"CVE Scanner: Will scan {lib['name']} v{lib['version']} from {lib['file_path']}")

        # Log native library filtering configuration
        if self.scan_config.get("scan_native_only", True):
            self.logger.info("CVE Scanner: Native library filtering ENABLED - focusing on native libraries only")
            self.logger.info(
                f"CVE Scanner: Java/Android libraries will be {'included' if self.scan_config.get('include_java_libraries', False) else 'excluded'}"
            )
        else:
            self.logger.info("CVE Scanner: Native library filtering DISABLED - scanning all library types")

        self.logger.info(
            f"CVE Scanner: {len(scannable_libraries)} libraries passed confidence and filtering thresholds"
        )
        self.logger.info(
            f"CVE Scanner: Confidence threshold is set to {self.scan_config['min_confidence']} (libraries need >= this confidence to be scanned)"
        )

        # Debug: Show confidence distribution for native libraries
        if detected_native_libs:
            confidences = [
                lib.get("confidence", 0)
                for lib in detected_native_libs
                if isinstance(lib, dict) and lib.get("confidence") is not None
            ]
            if confidences:
                min_conf = min(confidences)
                max_conf = max(confidences)
                avg_conf = sum(confidences) / len(confidences)
                above_threshold = sum(1 for c in confidences if c >= self.scan_config["min_confidence"])
                self.logger.info(
                    f"CVE Scanner: Library confidence range: {min_conf:.2f} - {max_conf:.2f} (avg: {avg_conf:.2f})"
                )
                self.logger.info(
                    f"CVE Scanner: {above_threshold}/{len(confidences)} libraries meet confidence threshold"
                )

        # Show scannable libraries, especially FFmpeg
        ffmpeg_scannable = [lib for lib in scannable_libraries if "ffmpeg" in lib["name"].lower()]
        if ffmpeg_scannable:
            self.logger.info(f"CVE Scanner: {len(ffmpeg_scannable)} FFmpeg libraries will be scanned:")
            for ffmpeg_lib in ffmpeg_scannable:
                self.logger.info(
                    f"CVE Scanner: FFmpeg scannable: {ffmpeg_lib['name']} {ffmpeg_lib['version']} (confidence: {ffmpeg_lib['confidence']:.2f})"
                )

        # Show example scannable libraries
        for i, lib in enumerate(scannable_libraries[:5]):
            self.logger.debug(
                f"CVE Scanner: Scannable lib {i+1}: {lib['name']} {lib['version']} (confidence: {lib['confidence']:.2f}, method: {lib['detection_method']})"
            )

        if not ffmpeg_scannable:
            self.logger.warning("CVE Scanner: No FFmpeg libraries passed confidence threshold for scanning")

        # Limit number of libraries to scan per source to avoid excessive API usage
        max_libs = self.scan_config["max_libraries_per_source"]
        if len(scannable_libraries) > max_libs:
            # Prioritize by: 1) Native libraries first, 2) High confidence, 3) Known vulnerable libraries
            def priority_score(lib):
                score = lib["confidence"]  # Base score is confidence

                # Boost native libraries significantly
                if "native" in lib["detection_method"].lower() or "native" in lib.get("source", "").lower():
                    score += 10  # Major boost for native libraries

                # Boost known vulnerable libraries (common CVE-prone libraries)
                vulnerable_patterns = ["ffmpeg", "openssl", "curl", "sqlite", "libpng", "libjpeg", "zlib"]
                lib_name_lower = lib["name"].lower()
                if any(pattern in lib_name_lower for pattern in vulnerable_patterns):
                    score += 5  # Boost for known vulnerable libraries

                # Boost critical categories
                critical_categories = ["security", "networking", "media"]
                if lib.get("category", "").lower() in critical_categories:
                    score += 2

                return score

            scannable_libraries.sort(key=priority_score, reverse=True)
            scannable_libraries = scannable_libraries[:max_libs]
            self.logger.info(f"Limited CVE scanning to top {max_libs} libraries by priority (native libs + confidence)")

            # Show what we're prioritizing
            native_count = sum(1 for lib in scannable_libraries if "native" in lib["detection_method"].lower())
            ffmpeg_count = sum(1 for lib in scannable_libraries if "ffmpeg" in lib["name"].lower())
            self.logger.info(
                f"CVE Scanner: Prioritized {native_count} native libraries (including {ffmpeg_count} FFmpeg) out of {len(scannable_libraries)} selected"
            )

        return scannable_libraries

    def _scan_libraries_for_cves(self, libraries: list[dict[str, Any]]) -> list[CVEVulnerability]:
        """Scan libraries for CVE vulnerabilities using multiple sources with improved timeout handling."""
        all_vulnerabilities = []

        # Perform health checks ONLY on enabled clients
        healthy_clients = {}

        # Double-check enabled sources to prevent health checks on disabled sources
        enabled_sources = []
        for source_name, source_config in self.sources_config.items():
            if source_config.get("enabled", False):
                enabled_sources.append(source_name)

        self.logger.info(f"CVE Scanner: Enabled sources in config: {enabled_sources}")
        self.logger.info(f"CVE Scanner: Initialized clients: {list(self.clients.keys())}")

        # Only health check clients that are both initialized AND enabled in config
        clients_to_check = {}
        for source, client in self.clients.items():
            if source in enabled_sources:
                clients_to_check[source] = client
            else:
                self.logger.warning(f"CVE Scanner: Skipping health check for {source} - disabled in configuration")

        self.logger.info(
            f"CVE Scanner: Starting health checks for {len(clients_to_check)} enabled clients: {list(clients_to_check.keys())}"
        )

        for source, client in clients_to_check.items():
            self.logger.debug(f"CVE Scanner: Checking health of {source} client (enabled)...")
            try:
                health_result = client.health_check()
                self.logger.debug(f"CVE Scanner: {source} health check returned: {health_result}")

                if health_result:
                    healthy_clients[source] = client
                    self.logger.info(f"CVE Scanner: ✓ {source} client is healthy")
                else:
                    self.logger.warning(f"CVE Scanner: ✗ {source} client failed health check (returned False)")
            except Exception as e:
                self.logger.error(f"CVE Scanner: ✗ {source} client health check threw exception: {e}")
                import traceback

                self.logger.debug(f"CVE Scanner: {source} health check traceback: {traceback.format_exc()}")

        self.logger.info(
            f"CVE Scanner: Health check results: {len(healthy_clients)}/{len(clients_to_check)} enabled clients healthy"
        )

        if not healthy_clients:
            self.logger.error("No healthy CVE clients available")
            return all_vulnerabilities

        # Calculate total futures and set realistic timeouts
        total_futures = len(libraries) * len(healthy_clients)
        overall_timeout = self.scan_config["overall_timeout_minutes"] * 60  # Convert to seconds
        per_future_timeout = min(self.scan_config["timeout_seconds"], overall_timeout // max(total_futures, 1))

        self.logger.info(
            f"CVE Scanner: Scanning {len(libraries)} libraries with {len(healthy_clients)} clients = {total_futures} total scans"
        )
        self.logger.info(f"CVE Scanner: Overall timeout: {overall_timeout}s, Per-scan timeout: {per_future_timeout}s")

        # Scan libraries in parallel with improved timeout handling
        with ThreadPoolExecutor(max_workers=self.scan_config["max_workers"]) as executor:
            future_to_library = {}

            for library in libraries:
                for source, client in healthy_clients.items():
                    future = executor.submit(
                        self._scan_single_library_with_retry, client, source, library["name"], library["version"]
                    )
                    future_to_library[future] = (source, library)

            # Collect results with improved error handling
            completed_count = 0
            failed_count = 0

            try:
                for future in as_completed(future_to_library, timeout=overall_timeout):
                    source, library = future_to_library[future]

                    try:
                        vulnerabilities = future.result(timeout=per_future_timeout)
                        completed_count += 1

                        if vulnerabilities:
                            self.logger.debug(
                                f"Found {len(vulnerabilities)} vulnerabilities for {library['name']} from {source}"
                            )
                            all_vulnerabilities.extend(vulnerabilities)
                        else:
                            self.logger.debug(f"No vulnerabilities found for {library['name']} from {source}")

                    except Exception as e:
                        failed_count += 1
                        self.logger.warning(f"CVE scan failed for {library['name']} via {source}: {e}")

                    # Progress logging
                    if (completed_count + failed_count) % 10 == 0:
                        progress = (completed_count + failed_count) / total_futures * 100
                        self.logger.info(
                            f"CVE Scanner: Progress {progress:.1f}% ({completed_count + failed_count}/{total_futures}) - {completed_count} successful, {failed_count} failed"
                        )

            except Exception as e:
                unfinished_count = total_futures - completed_count - failed_count
                self.logger.error(f"CVE scanning timeout/error: {e}")
                self.logger.error(f"CVE Scanner: {unfinished_count} (of {total_futures}) futures unfinished")

                # Cancel remaining futures to free resources
                for future in future_to_library:
                    if not future.done():
                        future.cancel()

        self.logger.info(
            f"CVE Scanner: Completed {completed_count}/{total_futures} scans successfully, {failed_count} failed"
        )

        # Remove duplicates based on CVE ID
        unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)

        return unique_vulnerabilities

    def _scan_single_library_with_retry(
        self, client, source: str, library_name: str, version: str
    ) -> list[CVEVulnerability]:
        """Scan a single library using a specific CVE client with retry logic."""
        import time

        last_exception = None

        for attempt in range(self.scan_config["retry_attempts"] + 1):
            try:
                self.logger.debug(
                    f"CVE Scanner: Scanning {library_name}:{version} via {source} (attempt {attempt + 1})"
                )

                # Add delay between client operations to prevent session conflicts
                if attempt > 0 or source == "nvd":
                    delay = 1.0 if source == "nvd" else 0.5  # Longer delay for NVD
                    self.logger.debug(f"CVE Scanner: Adding {delay}s delay before {source} scan")
                    time.sleep(delay)

                vulnerabilities = client.search_vulnerabilities_with_cache(library_name, version)
                self.logger.debug(f"[{library_name}]  Number of vulnerabilities {len(vulnerabilities)}")

                # Add source metadata and library attribution to vulnerabilities
                for vuln in vulnerabilities:
                    vuln.source = source
                    vuln.source_library = library_name  # Track which library this CVE was found for

                if attempt > 0:
                    self.logger.debug(
                        f"CVE Scanner: {library_name}:{version} via {source} succeeded on retry {attempt}"
                    )

                return vulnerabilities

            except Exception as e:
                last_exception = e

                # Check if this is a rate limiting error
                error_str = str(e).lower()
                is_rate_limit = any(term in error_str for term in ["rate limit", "429", "too many requests", "quota"])
                is_timeout = any(term in error_str for term in ["timeout", "connection", "network"])

                if attempt < self.scan_config["retry_attempts"]:
                    if is_rate_limit:
                        # Longer delay for rate limiting
                        delay = self.scan_config["retry_delay_seconds"] * (2**attempt)  # Exponential backoff
                        self.logger.debug(
                            f"CVE Scanner: Rate limit detected for {library_name} via {source}, retrying in {delay}s"
                        )
                        time.sleep(delay)
                    elif is_timeout:
                        # Shorter delay for timeouts
                        delay = self.scan_config["retry_delay_seconds"]
                        self.logger.debug(f"CVE Scanner: Timeout for {library_name} via {source}, retrying in {delay}s")
                        time.sleep(delay)
                    else:
                        # Unknown error, short delay
                        time.sleep(1)
                        self.logger.debug(
                            f"CVE Scanner: Error scanning {library_name} via {source} (attempt {attempt + 1}): {e}"
                        )
                else:
                    self.logger.warning(
                        f"CVE Scanner: Failed to scan {library_name}:{version} via {source} after {self.scan_config['retry_attempts'] + 1} attempts: {last_exception}"
                    )

        return []

    def _scan_single_library(self, client, source: str, library_name: str, version: str) -> list[CVEVulnerability]:
        """Scan a single library using a specific CVE client (legacy method for compatibility)."""
        return self._scan_single_library_with_retry(client, source, library_name, version)

    def _deduplicate_vulnerabilities(self, vulnerabilities: list[CVEVulnerability]) -> list[CVEVulnerability]:
        """Remove duplicate vulnerabilities based on CVE ID."""
        seen_cves = {}
        unique_vulns = []

        for vuln in vulnerabilities:
            cve_id = vuln.cve_id

            if cve_id not in seen_cves:
                seen_cves[cve_id] = vuln
                unique_vulns.append(vuln)
            else:
                # Keep the vulnerability with higher severity or more recent data
                existing = seen_cves[cve_id]
                if vuln.severity.value > existing.severity.value or (
                    vuln.modified_date and existing.modified_date and vuln.modified_date > existing.modified_date
                ):
                    seen_cves[cve_id] = vuln
                    # Replace in unique list
                    for i, existing_vuln in enumerate(unique_vulns):
                        if existing_vuln.cve_id == cve_id:
                            unique_vulns[i] = vuln
                            break

        return unique_vulns

    def _create_security_findings(
        self, vulnerabilities: list[CVEVulnerability], libraries: list[dict[str, Any]], context: Any | None = None
    ) -> list[SecurityFinding]:
        """Create security findings from CVE vulnerabilities with enhanced library mapping."""
        findings = []

        # Create library lookup for vulnerability attribution
        library_lookup = {lib["name"]: lib for lib in libraries}

        # Create detailed CVE-to-library mapping for JSON export
        cve_library_mapping = self._create_cve_library_mapping(vulnerabilities, library_lookup)

        # Group vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.CRITICAL]
        high_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.HIGH]
        medium_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.MEDIUM]
        low_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.LOW]

        # Create findings for each severity level with library attribution and file locations
        if critical_vulns:
            findings.append(
                self._create_enhanced_severity_finding(
                    critical_vulns,
                    AnalysisSeverity.CRITICAL,
                    "Critical CVE Vulnerabilities Detected",
                    "Application uses libraries with critical CVE vulnerabilities that allow remote code execution or complete system compromise.",
                    library_lookup,
                    cve_library_mapping,
                    context,
                )
            )

        if high_vulns:
            findings.append(
                self._create_enhanced_severity_finding(
                    high_vulns,
                    AnalysisSeverity.HIGH,
                    "High-Risk CVE Vulnerabilities Found",
                    "Application contains libraries with high-risk CVE vulnerabilities that could lead to significant security breaches.",
                    library_lookup,
                    cve_library_mapping,
                    context,
                )
            )

        if medium_vulns:
            findings.append(
                self._create_enhanced_severity_finding(
                    medium_vulns,
                    AnalysisSeverity.MEDIUM,
                    "Medium-Risk CVE Vulnerabilities Identified",
                    "Application uses libraries with medium-risk CVE vulnerabilities that should be addressed.",
                    library_lookup,
                    cve_library_mapping,
                    context,
                )
            )

        if low_vulns:
            findings.append(
                self._create_enhanced_severity_finding(
                    low_vulns,
                    AnalysisSeverity.LOW,
                    "Low-Risk CVE Vulnerabilities Present",
                    "Application contains libraries with low-risk CVE vulnerabilities for awareness.",
                    library_lookup,
                    cve_library_mapping,
                    context,
                )
            )

        # Add enhanced summary finding with detailed CVE mapping
        if vulnerabilities:
            total_vulns = len(vulnerabilities)
            scanned_libs = len(libraries)

            # Create library-specific summary from mapping
            library_summary = cve_library_mapping["library_summary"]
            affected_libraries = len(library_summary)

            summary_evidence = [
                f"Total CVE vulnerabilities found: {total_vulns}",
                f"Libraries scanned: {scanned_libs}",
                f"Libraries with vulnerabilities: {affected_libraries}",
                f"Critical: {len(critical_vulns)}, High: {len(high_vulns)}, Medium: {len(medium_vulns)}, Low: {len(low_vulns)}",
                f"CVE sources used: {', '.join(self.clients.keys())}",
            ]

            # Add per-library breakdown for top affected libraries
            if library_summary:
                summary_evidence.append("Top affected libraries:")
                # Sort libraries by total CVE count
                sorted_libs = sorted(library_summary.items(), key=lambda x: sum(x[1].values()), reverse=True)[
                    :5
                ]  # Show top 5

                for lib_name, counts in sorted_libs:
                    total_lib_cves = sum(counts.values())
                    lib_info = library_lookup.get(lib_name, {})
                    lib_version = lib_info.get("version", "unknown")
                    summary_evidence.append(f"  • {lib_name} (v{lib_version}): {total_lib_cves} CVEs")

            # Store complete CVE mapping in summary finding for JSON export
            summary_additional_data = {
                "complete_cve_mapping": cve_library_mapping,
                "scan_metadata": {
                    "libraries_scanned": scanned_libs,
                    "libraries_with_vulnerabilities": affected_libraries,
                    "vulnerability_distribution": {
                        "critical": len(critical_vulns),
                        "high": len(high_vulns),
                        "medium": len(medium_vulns),
                        "low": len(low_vulns),
                    },
                    "cve_sources": list(self.clients.keys()),
                },
            }

            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title="CVE Vulnerability Scan Summary",
                    description=f"Comprehensive CVE scan completed. Found {total_vulns} vulnerabilities across {affected_libraries} vulnerable libraries.",
                    evidence=summary_evidence,
                    recommendations=[
                        "Prioritize fixing critical and high-severity vulnerabilities",
                        "Update vulnerable libraries to patched versions",
                        "Implement automated CVE monitoring for dependencies",
                        "Consider alternative libraries for components with multiple CVEs",
                        "Review application's exposure to identified vulnerabilities",
                    ],
                    additional_data=summary_additional_data,
                )
            )

        return findings

    def _get_temporal_directory(self, analysis_results: dict[str, Any]) -> str:
        """Get temporal directory path from analysis results."""
        try:
            # Try to get temporal directory from analysis context
            context = analysis_results.get("_analysis_context", {})
            if hasattr(context, "temporal_directory"):
                return str(context.temporal_directory)
            elif isinstance(context, dict) and "temporal_directory" in context:
                return str(context["temporal_directory"])

            # Try to get from temporal analysis results
            temporal_info = analysis_results.get("temporal_analysis", {})
            if isinstance(temporal_info, dict) and "base_directory" in temporal_info:
                return temporal_info["base_directory"]

            # Fallback: try to find in any module that might have temporal info
            for _module_name, module_results in analysis_results.items():
                if hasattr(module_results, "temporal_directory"):
                    return str(module_results.temporal_directory)

            return None
        except Exception as e:
            self.logger.debug(f"Could not determine temporal directory: {e}")
            return None

    def _filter_relevant_cves(
        self, vulnerabilities: list[CVEVulnerability], scannable_libraries: list[dict[str, Any]]
    ) -> list[CVEVulnerability]:
        """Filter out CVEs that are clearly not relevant to mobile/Android applications."""
        relevant_cves = []
        library_names = {lib["name"].lower() for lib in scannable_libraries}

        # Keywords that indicate clearly irrelevant CVEs for mobile apps
        irrelevant_keywords = [
            # Network hardware
            "3com",
            "cisco",
            "router",
            "switch",
            "gateway",
            "firewall",
            "officeconnect",
            "linksys",
            "netgear",
            "tp-link",
            # Desktop/Server software
            "microsoft data access",
            "mdac",
            "vmware",
            "esxi",
            "vcenter",
            "windows server",
            "internet information services",
            "iis",
            "oracle database",
            "sql server",
            "postgresql server",
            # Other non-mobile platforms
            "mainframe",
            "as/400",
            "z/os",
            "solaris",
            "aix",
            "cisco ios",
            "juniper junos",
            "palo alto",
        ]

        for vuln in vulnerabilities:
            is_relevant = True

            # Check CVE summary and description for irrelevant keywords
            summary_lower = vuln.summary.lower() if vuln.summary else ""
            description_lower = (vuln.description or "").lower()

            # Filter out clearly irrelevant CVEs
            for keyword in irrelevant_keywords:
                if keyword in summary_lower or keyword in description_lower:
                    self.logger.debug(f"CVE Scanner: Filtering out irrelevant CVE {vuln.cve_id} (keyword: {keyword})")
                    is_relevant = False
                    break

            if not is_relevant:
                continue

            # CRITICAL FIX: For targeted library searches, be more permissive
            # Since we're scanning specific libraries by name/version, CVEs returned
            # from those targeted searches are by definition relevant to those libraries
            library_match = False

            # Check if CVE source library matches our scanned libraries (most reliable)
            if hasattr(vuln, "source_library") and vuln.source_library:
                source_lib_normalized = self._normalize_library_name(vuln.source_library)
                for detected_lib_name in library_names:
                    detected_normalized = self._normalize_library_name(detected_lib_name)
                    if source_lib_normalized == detected_normalized:
                        library_match = True
                        self.logger.debug(
                            f"CVE Scanner: Including CVE {vuln.cve_id} - source library match: {vuln.source_library}"
                        )
                        break

            # Fallback: Check affected_libraries field
            if not library_match and vuln.affected_libraries:
                for affected_lib in vuln.affected_libraries:
                    lib_name_normalized = self._normalize_library_name(affected_lib.name)

                    # Check if this matches any of our detected native libraries
                    for detected_lib_name in library_names:
                        detected_normalized = self._normalize_library_name(detected_lib_name)
                        if lib_name_normalized == detected_normalized:
                            library_match = True
                            self.logger.debug(
                                f"CVE Scanner: Including CVE {vuln.cve_id} - affected library match: {affected_lib.name}"
                            )
                            break

                    if library_match:
                        break

            # IMPORTANT: If we can't match by library name but the CVE mentions
            # the library name in summary/description, and we searched for that library, include it
            if not library_match:
                for detected_lib_name in library_names:
                    if detected_lib_name in summary_lower or detected_lib_name in description_lower:
                        library_match = True
                        self.logger.debug(
                            f"CVE Scanner: Including CVE {vuln.cve_id} - library mentioned in text: {detected_lib_name}"
                        )
                        break

            # Include CVEs that match our detected libraries
            if library_match:
                relevant_cves.append(vuln)
            else:
                self.logger.debug(f"CVE Scanner: Filtering out CVE {vuln.cve_id} - no library match found")

        return relevant_cves

    def _normalize_library_name(self, name: str) -> str:
        """Normalize library name for comparison."""
        return name.lower().replace("-", "_").replace(".", "_")

    def _create_cve_library_mapping(
        self, vulnerabilities: list[CVEVulnerability], library_lookup: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Create detailed CVE-to-library mapping for JSON export."""
        cve_mapping = {}
        library_cve_counts = {}

        for vuln in vulnerabilities:
            # Find which library this CVE was discovered for
            affected_library = None
            library_info = None

            # Try to match based on affected_libraries in CVE data
            if vuln.affected_libraries:
                for affected_lib in vuln.affected_libraries:
                    normalized_name = self._normalize_library_name(affected_lib.name)
                    for lib_name, lib_data in library_lookup.items():
                        if self._normalize_library_name(lib_name) == normalized_name:
                            affected_library = lib_name
                            library_info = lib_data
                            break
                    if affected_library:
                        break

            # Fallback: match based on CVE source metadata if available
            if not affected_library and hasattr(vuln, "source_library"):
                affected_library = vuln.source_library
                library_info = library_lookup.get(affected_library)

            if affected_library and library_info:
                # Count CVEs per library
                if affected_library not in library_cve_counts:
                    library_cve_counts[affected_library] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                library_cve_counts[affected_library][vuln.severity.value.lower()] += 1

                # Store detailed CVE information
                cve_info = {
                    "cve_id": vuln.cve_id,
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "summary": vuln.summary,
                    "library_name": affected_library,
                    "library_version": library_info.get("version", "unknown"),
                    "library_path": library_info.get("detection_source", "unknown"),
                    "detection_method": library_info.get("detection_method", "unknown"),
                    "source_database": vuln.source,
                    "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                    "references": vuln.references[:3],  # Limit references for readability
                }
                cve_mapping[vuln.cve_id] = cve_info

        return {
            "cve_details": cve_mapping,
            "library_summary": library_cve_counts,
            "total_cves": len(vulnerabilities),
            "libraries_affected": len(library_cve_counts),
        }

    def _create_enhanced_severity_finding(
        self,
        vulnerabilities: list[CVEVulnerability],
        severity: AnalysisSeverity,
        title: str,
        description: str,
        library_lookup: dict[str, dict[str, Any]],
        cve_mapping: dict[str, Any],
        context: Any | None = None,
    ) -> SecurityFinding:
        """Create enhanced security finding with CVE-to-library attribution."""
        evidence = []
        cve_references = []

        # Group CVEs by affected library for better organization
        library_cves = {}
        unattributed_cves = []

        for vuln in vulnerabilities[:10]:  # Limit for terminal readability
            affected_library = None

            # Find which library this CVE affects
            if vuln.cve_id in cve_mapping["cve_details"]:
                affected_library = cve_mapping["cve_details"][vuln.cve_id]["library_name"]

            if affected_library:
                if affected_library not in library_cves:
                    library_cves[affected_library] = []
                library_cves[affected_library].append(vuln)
            else:
                unattributed_cves.append(vuln)

        # Create evidence with library attribution INCLUDING all .so file paths (as requested)
        for library_name, library_vulns in library_cves.items():
            library_info = library_lookup.get(library_name, {})
            library_version = library_info.get("version", "unknown")
            all_so_files = library_info.get("all_so_files", [])
            main_file_path = library_info.get("file_path", "unknown path")

            # Show library name with version and ALL related .so files (as requested by user)
            if all_so_files and len(all_so_files) > 1:
                evidence.append(f"📦 {library_name} (v{library_version}) - {len(all_so_files)} native binaries:")
                for so_file in all_so_files:
                    evidence.append(f"   📄 {so_file}")
            else:
                evidence.append(f"📦 {library_name} (v{library_version}) - Path: {main_file_path}")

            for vuln in library_vulns:
                evidence_line = f"  • {vuln.cve_id}"
                if vuln.cvss_score:
                    evidence_line += f" (CVSS: {vuln.cvss_score})"
                # Use first 150 chars instead of 100 for better context
                evidence_line += f": {vuln.summary[:150]}"
                if len(vuln.summary) > 150:
                    evidence_line += "..."
                evidence.append(evidence_line)

            # Collect unique references
            for vuln in library_vulns:
                for ref in vuln.references[:2]:  # Limit references per CVE
                    if ref not in cve_references:
                        cve_references.append(ref)

        # Add unattributed CVEs if any
        for vuln in unattributed_cves:
            evidence_line = f"⚠️ {vuln.cve_id}"
            if vuln.cvss_score:
                evidence_line += f" (CVSS: {vuln.cvss_score})"
            evidence_line += f": {vuln.summary[:150]}"
            if len(vuln.summary) > 150:
                evidence_line += "..."
            evidence.append(evidence_line)

            for ref in vuln.references[:2]:
                if ref not in cve_references:
                    cve_references.append(ref)

        if len(vulnerabilities) > 10:
            evidence.append(f"... and {len(vulnerabilities) - 10} more vulnerabilities")

        # Enhanced recommendations with library-specific guidance
        recommendations = [
            "Update affected libraries to patched versions immediately",
            f"Review {len(library_cves)} affected libraries for available security patches",
            "Prioritize updates for libraries with CRITICAL and HIGH severity CVEs",
            "Implement workarounds if patches are not immediately available",
            "Monitor security advisories for additional updates",
        ]

        if severity == AnalysisSeverity.CRITICAL:
            recommendations.insert(0, "🚨 URGENT: Address critical vulnerabilities immediately")
            recommendations.append("Consider temporarily disabling affected features if necessary")

        # Store detailed CVE data in additional_data for JSON export
        additional_data = {
            "cve_library_mapping": {lib: [vuln.cve_id for vuln in vulns] for lib, vulns in library_cves.items()},
            "detailed_cves": [vuln.to_dict() for vuln in vulnerabilities],
            "affected_libraries": list(library_cves.keys()),
            "severity_counts": {
                "total": len(vulnerabilities),
                "by_library": {lib: len(vulns) for lib, vulns in library_cves.items()},
            },
        }

        # Create file location for the primary affected native library if available
        file_location = None
        if context and library_cves:
            try:
                # Find the first library with .so files to create a file location
                for library_name, _library_vulns in library_cves.items():
                    library_info = library_lookup.get(library_name, {})
                    all_so_files = library_info.get("all_so_files", [])
                    if all_so_files:
                        # Use the first .so file as primary location (e.g., "lib/arm64-v8a/libffmpeg.so")
                        primary_so_file = all_so_files[0]
                        # For CVE findings, we don't have a specific offset, so we use offset 0 (base address)
                        file_location = context.create_native_file_location(primary_so_file, offset=0)
                        self.logger.debug(f"Created file location for CVE finding: {file_location.uri}")
                        break
            except Exception as e:
                self.logger.warning(f"Could not create file location for CVE finding: {e}")

        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            cve_references=cve_references,
            additional_data=additional_data,
            file_location=file_location,
        )

    def _create_severity_finding(
        self, vulnerabilities: list[CVEVulnerability], severity: AnalysisSeverity, title: str, description: str
    ) -> SecurityFinding:
        """Create a security finding for vulnerabilities of a specific severity."""
        evidence = []
        cve_references = []

        for vuln in vulnerabilities[:10]:  # Limit to first 10 for readability
            evidence_line = f"{vuln.cve_id}"
            if vuln.cvss_score:
                evidence_line += f" (CVSS: {vuln.cvss_score})"
            evidence_line += f": {vuln.summary[:100]}..."
            evidence.append(evidence_line)

            # Collect unique references
            for ref in vuln.references[:2]:  # Limit references per CVE
                if ref not in cve_references:
                    cve_references.append(ref)

        if len(vulnerabilities) > 10:
            evidence.append(f"... and {len(vulnerabilities) - 10} more vulnerabilities")

        recommendations = [
            "Immediately update affected libraries to patched versions",
            "Review CVE details and assess impact on your application",
            "Implement workarounds if patches are not immediately available",
            "Monitor security advisories for additional updates",
            "Consider security testing for affected functionality",
        ]

        if severity == AnalysisSeverity.CRITICAL:
            recommendations.insert(0, "URGENT: Address critical vulnerabilities immediately")
            recommendations.append("Consider temporarily disabling affected features if necessary")

        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _is_native_library(self, library_name: str, detection_method: str, source: str) -> bool:
        """
        Determine if a library is a native library that should be scanned for CVEs.

        Native libraries (like FFmpeg, OpenSSL, etc.) are more likely to have CVEs
        than Java/Android libraries.

        Args:
            library_name: Name of the library
            detection_method: Method used to detect the library
            source: Source of the library detection

        Returns:
            True if this is considered a native library worth scanning
        """
        library_name_lower = library_name.lower()
        detection_method_lower = detection_method.lower()
        source_lower = source.lower()

        # Check if detected as native by detection method or source
        if "native" in detection_method_lower or "native" in source_lower:
            return True

        # Check against native library patterns from config
        patterns = self.scan_config.get("native_library_patterns", [])
        for pattern in patterns:
            pattern_lower = pattern.lower().replace("*", "")
            if pattern_lower in library_name_lower:
                self.logger.debug(f"CVE Scanner: {library_name} matches native pattern: {pattern}")
                return True

        # Additional heuristics for native libraries
        native_indicators = [
            ".so",  # Shared object files
            "lib",  # Common prefix for native libs
            "jni",  # Java Native Interface
            "ndk",  # Android NDK
            "c++",  # C++ libraries
            "opencv",  # Computer vision library
            "boost",  # C++ boost libraries
            "protobuf",  # Protocol buffers (often native)
            "grpc",  # gRPC (often native)
            "tensorflow",  # TensorFlow (often native)
        ]

        for indicator in native_indicators:
            if indicator in library_name_lower:
                self.logger.debug(f"CVE Scanner: {library_name} identified as native (indicator: {indicator})")
                return True

        # Libraries that should be excluded from CVE scanning (very unlikely to have relevant CVEs)
        # Note: Reduced list to be less aggressive - many Java libraries can have CVEs
        definitely_exclude_patterns = [
            "androidx",
            "android.support",
            "com.google.android",  # Core Android libraries
            "junit",
            "mockito",  # Test libraries
            "butterknife",  # View binding
            "glide",
            "picasso",  # Image loading (less likely to have CVEs)
        ]

        # Libraries that SHOULD be scanned even if they seem like Java/Android libraries
        # These are known to have CVEs
        force_include_patterns = [
            "okhttp",  # HTTP client - known to have CVEs
            "retrofit",  # REST client - can have CVEs
            "gson",  # JSON library - can have CVEs
            "jackson",  # JSON library - known CVEs
            "apache",  # Apache libraries - known to have CVEs
            "commons",  # Apache Commons - known CVEs
            "spring",  # Spring framework - known CVEs
            "struts",  # Apache Struts - many CVEs
            "log4j",  # Logging library - major CVEs
            "slf4j",  # Logging library - can have CVEs
        ]

        # Check force-include patterns first
        for pattern in force_include_patterns:
            if pattern in library_name_lower:
                self.logger.debug(f"CVE Scanner: {library_name} force-included for scanning (pattern: {pattern})")
                return True

        # Check exclude patterns
        for pattern in definitely_exclude_patterns:
            if pattern in library_name_lower:
                self.logger.debug(f"CVE Scanner: {library_name} excluded from scanning (pattern: {pattern})")
                return False

        # Default behavior: be more inclusive for CVE scanning
        # If scan_native_only is enabled, be more liberal about what counts as "native"
        if self.scan_config.get("scan_native_only", True):
            # Check if it looks like a substantial third-party library worth scanning
            substantial_library_patterns = [
                "firebase",  # Google Firebase (can have CVEs)
                "google",  # Other Google libraries
                "facebook",  # Facebook libraries
                "squareup",  # Square libraries (OkHttp, Retrofit)
                "reactivex",  # RxJava (can have vulnerabilities)
                "org.",  # Org-domain libraries (Apache, etc.)
                "io.",  # IO-domain libraries
                "net.",  # Network libraries
                "crypto",  # Crypto libraries
                "security",  # Security libraries
                "ssl",  # SSL/TLS libraries
                "http",  # HTTP libraries
                "network",  # Network libraries
            ]

            for pattern in substantial_library_patterns:
                if pattern in library_name_lower:
                    self.logger.debug(
                        f"CVE Scanner: {library_name} included as substantial library (pattern: {pattern})"
                    )
                    return True

            self.logger.debug(f"CVE Scanner: {library_name} defaulting to non-native (conservative approach)")
            return False

        # If not scan_native_only, include all libraries
        return True

    def get_scan_statistics(self) -> dict[str, Any]:
        """Get CVE scanning statistics."""
        stats = {
            "clients_initialized": len(self.clients),
            "cache_stats": self.cache_manager.get_cache_stats() if self.cache_manager else {},
            "sources_enabled": [
                source for source, config in self.sources_config.items() if config.get("enabled", False)
            ],
        }

        # Get rate limit status from clients
        for source, client in self.clients.items():
            try:
                stats[f"{source}_rate_limit"] = client.get_rate_limit_status()
            except Exception as e:
                self.logger.debug(f"Could not get rate limit status for {source}: {e}")

        return stats
