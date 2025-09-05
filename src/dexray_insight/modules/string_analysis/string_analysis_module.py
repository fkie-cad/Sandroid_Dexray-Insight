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
String Analysis Module - Refactored Main Module.

String extraction and analysis module using specialized extractors and filters.
Refactored to use submodules following Single Responsibility Principle.

Phase 8 TDD Refactoring: Main module now delegates to specialized extractors
and filters from dedicated submodules.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.core.base_classes import AnalysisStatus
from dexray_insight.core.base_classes import BaseAnalysisModule
from dexray_insight.core.base_classes import BaseResult
from dexray_insight.core.base_classes import register_module

# Import from submodules
from .extractors import StringExtractor
from .filters import AndroidPropertiesFilter
from .filters import DomainFilter
from .filters import EmailFilter
from .filters import NetworkFilter
from .validators import StringValidators


@dataclass
class StringAnalysisResult(BaseResult):
    """Result class for string analysis."""

    emails: list[str] = None
    ip_addresses: list[str] = None
    urls: list[str] = None
    domains: list[str] = None
    android_properties: dict[str, str] = None
    all_strings: list[str] = None  # Store all filtered strings for security analysis
    total_strings_analyzed: int = 0

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.emails is None:
            self.emails = []
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.urls is None:
            self.urls = []
        if self.domains is None:
            self.domains = []
        if self.android_properties is None:
            self.android_properties = {}
        if self.all_strings is None:
            self.all_strings = []

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        base_dict = super().to_dict()
        base_dict.update(
            {
                "emails": self.emails,
                "ip_addresses": self.ip_addresses,
                "urls": self.urls,
                "domains": self.domains,
                "android_properties": self.android_properties,
                "all_strings": self.all_strings,
                "total_strings_analyzed": self.total_strings_analyzed,
            }
        )
        return base_dict


@register_module("string_analysis")
class StringAnalysisModule(BaseAnalysisModule):
    """
    String extraction and analysis module.

    Phase 8 TDD Refactoring: Refactored to use specialized extractors and
    filters from dedicated submodules following SRP.
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize StringAnalysisModule with configuration."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

        # Configuration options
        self.min_string_length = config.get("min_string_length", 3)
        self.exclude_patterns = config.get("exclude_patterns", [])

        # Pattern enablement flags
        self.patterns = {
            "email_addresses": config.get("email_addresses", True),
            "ip_addresses": config.get("ip_addresses", True),
            "urls": config.get("urls", True),
            "domains": config.get("domains", True),
            "android_properties": config.get("android_properties", True),
        }

        # Initialize specialized components
        self.string_extractor = StringExtractor(
            {"min_string_length": self.min_string_length, "exclude_patterns": self.exclude_patterns}
        )
        self.email_filter = EmailFilter()
        self.network_filter = NetworkFilter()
        self.domain_filter = DomainFilter()
        self.android_properties_filter = AndroidPropertiesFilter()
        self.validators = StringValidators()

        # Validate configuration
        if not self._validate_configuration():
            self.logger.error("Invalid string analysis configuration")

    def get_dependencies(self) -> list[str]:
        """Dependencies: May use results from dotnet and native analysis if available."""
        return []  # No hard dependencies, but can utilize other modules if available

    def analyze(self, apk_path: str, context: AnalysisContext) -> StringAnalysisResult:
        """
        Perform string analysis using specialized extractors and filters.

        Refactored coordinator function that delegates to specialized extraction and
        filtering components following the Single Responsibility Principle. Each
        filtering concern is handled by a dedicated filter with its own logic.

        Args:
            apk_path: Path to the APK file
            context: Analysis context

        Returns:
            StringAnalysisResult with comprehensive string analysis results
        """
        start_time = time.time()

        self.logger.info(f"Starting string analysis for {apk_path}")
        self.logger.debug(f"String analysis module starting for {apk_path}")

        try:
            # Phase 1: Extract all strings from available sources
            all_strings = self.string_extractor.extract_all_strings(context)

            # Phase 2: Apply specialized filters
            results = self._apply_all_filters(all_strings)

            # Phase 3: Finalize results and statistics
            execution_time = time.time() - start_time

            # Log comprehensive summary
            self._log_analysis_summary(results)

            return StringAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                emails=results["emails"],
                ip_addresses=results["ip_addresses"],
                urls=results["urls"],
                domains=results["domains"],
                android_properties=results["android_properties"],
                all_strings=list(all_strings),  # Convert set to list for JSON serialization
                total_strings_analyzed=len(all_strings),
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"String analysis failed: {str(e)}")

            return StringAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                total_strings_analyzed=0,
            )

    def _apply_all_filters(self, strings: set[str]) -> dict[str, list]:
        """
        Apply all enabled filters to the string collection.

        Args:
            strings: Set of strings to filter

        Returns:
            Dictionary with filtered results for each category
        """
        results = {"emails": [], "ip_addresses": [], "urls": [], "domains": [], "android_properties": {}}

        self.logger.debug(f"🔍 CATEGORIZING {len(strings)} FILTERED STRINGS:")

        # Apply email filter
        if self.patterns.get("email_addresses", True):
            results["emails"] = self.email_filter.filter_emails(strings)
            self.logger.debug(f"   📧 Email addresses found: {len(results['emails'])}")
            if results["emails"] and len(results["emails"]) <= 5:
                self.logger.debug(f"      Sample emails: {results['emails']}")

        # Apply network filter for IPs and URLs
        if self.patterns.get("ip_addresses", True):
            results["ip_addresses"] = self.network_filter.filter_ip_addresses(strings)
            self.logger.debug(f"   🌐 IP addresses found: {len(results['ip_addresses'])}")
            if results["ip_addresses"] and len(results["ip_addresses"]) <= 5:
                self.logger.debug(f"      Sample IPs: {results['ip_addresses']}")

        if self.patterns.get("urls", True):
            results["urls"] = self.network_filter.filter_urls(strings)
            self.logger.debug(f"   🔗 URLs found: {len(results['urls'])}")
            if results["urls"] and len(results["urls"]) <= 5:
                self.logger.debug(f"      Sample URLs: {results['urls']}")

        # Apply domain filter
        if self.patterns.get("domains", True):
            results["domains"] = self.domain_filter.filter_domains(strings)
            self.logger.debug(f"   🏠 Domains found: {len(results['domains'])}")
            if results["domains"] and len(results["domains"]) <= 5:
                self.logger.debug(f"      Sample domains: {results['domains']}")

        # Apply Android properties filter
        if self.patterns.get("android_properties", True):
            # Convert strings set to list for Android properties filter
            android_props, remaining = self.android_properties_filter.filter_android_properties(list(strings))
            results["android_properties"] = android_props
            self.logger.debug(f"   🤖 Android properties found: {len(android_props)}")
            if android_props and len(android_props) <= 3:
                self.logger.debug(f"      Found properties: {list(android_props.keys())}")

        return results

    def _log_analysis_summary(self, results: dict[str, list]):
        """
        Log comprehensive analysis summary.

        Args:
            results: Dictionary with analysis results
        """
        self.logger.info("📊 STRING ANALYSIS SUMMARY:")
        self.logger.info(f"   📧 Email addresses: {len(results['emails'])}")
        self.logger.info(f"   🌐 IP addresses: {len(results['ip_addresses'])}")
        self.logger.info(f"   🔗 URLs: {len(results['urls'])}")
        self.logger.info(f"   🏠 Domain names: {len(results['domains'])}")
        self.logger.info(f"   🤖 Android properties: {len(results['android_properties'])}")

        total_found = (
            len(results["emails"])
            + len(results["ip_addresses"])
            + len(results["urls"])
            + len(results["domains"])
            + len(results["android_properties"])
        )
        self.logger.info(f"   ✅ Total categorized strings: {total_found}")

        # Log interesting findings
        if results["android_properties"]:
            security_props = self.android_properties_filter.get_security_relevant_properties(
                results["android_properties"]
            )
            if security_props:
                self.logger.info(f"   🔒 Security-relevant properties found: {len(security_props)}")

        if results["ip_addresses"]:
            ip_classifications = self.network_filter.classify_ip_addresses(results["ip_addresses"])
            public_ips = len(ip_classifications.get("Public IPv4", []))
            if public_ips > 0:
                self.logger.info(f"   🌍 Public IP addresses found: {public_ips}")

    def _validate_configuration(self) -> bool:
        """
        Validate module configuration using validators.

        Returns:
            True if configuration is valid
        """
        config = {
            "min_string_length": self.min_string_length,
            "exclude_patterns": self.exclude_patterns,
            "patterns": self.patterns,
        }

        validation_report = self.validators.get_validation_report(config)

        if not validation_report["valid"]:
            for error in validation_report["errors"]:
                self.logger.error(f"Configuration error: {error}")
            return False

        for warning in validation_report["warnings"]:
            self.logger.warning(f"Configuration warning: {warning}")

        # Validate component configurations
        if not self.string_extractor.validate_configuration():
            self.logger.error("String extractor configuration is invalid")
            return False

        self.logger.debug(f"String analysis configuration validated: {validation_report['config_summary']}")
        return True

    def validate_config(self) -> bool:
        """Validate module configuration (public interface)."""
        return self._validate_configuration()

    def get_analysis_capabilities(self) -> dict[str, bool]:
        """
        Get current analysis capabilities based on configuration.

        Returns:
            Dictionary showing which analysis types are enabled
        """
        return {
            "email_extraction": self.patterns.get("email_addresses", True),
            "ip_extraction": self.patterns.get("ip_addresses", True),
            "url_extraction": self.patterns.get("urls", True),
            "domain_extraction": self.patterns.get("domains", True),
            "android_properties_extraction": self.patterns.get("android_properties", True),
            "multi_source_extraction": True,  # Always available
            "comprehensive_filtering": True,  # Always available
        }
