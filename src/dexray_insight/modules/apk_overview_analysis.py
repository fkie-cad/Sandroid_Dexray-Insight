#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK overview analysis module for extracting comprehensive APK metadata."""

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

import logging
import time
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any

from ..apk_overview.app import analyze_apk
from ..apk_overview.app import parse_apk
from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisStatus
from ..core.base_classes import BaseAnalysisModule
from ..core.base_classes import BaseResult
from ..core.base_classes import register_module
from ..Utils.file_utils import split_path_file_extension


@dataclass
class APKOverviewResult(BaseResult):
    """Result class for APK overview analysis."""

    general_info: dict[str, Any] = field(default_factory=dict)
    components: dict[str, Any] = field(default_factory=dict)
    permissions: dict[str, Any] = field(default_factory=dict)
    certificates: dict[str, Any] = field(default_factory=dict)
    native_libs: list[str] = field(default_factory=list)
    directory_listing: list[str] = field(default_factory=list)
    is_cross_platform: bool = False
    cross_platform_framework: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        base_dict = super().to_dict()
        base_dict.update(
            {
                "general_info": self.general_info,
                "components": self.components,
                "permissions": self.permissions,
                "certificates": self.certificates,
                "native_libs": self.native_libs,
                "directory_listing": self.directory_listing,
                "is_cross_platform": self.is_cross_platform,
                "cross_platform_framework": self.cross_platform_framework,
            }
        )
        return base_dict


@register_module("apk_overview")
class APKOverviewModule(BaseAnalysisModule):
    """Module for comprehensive APK overview analysis."""

    def __init__(self, config: dict[str, Any]):
        """Initialize APKOverviewAnalysisModule with configuration."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)

    def get_name(self) -> str:
        """Get the module name."""
        return "APK Overview Analysis"

    def get_description(self) -> str:
        """Get the module description."""
        return "Extracts comprehensive APK metadata, components, permissions, and certificates"

    def get_dependencies(self) -> list[str]:
        """Get module dependencies."""
        return []  # APK overview has no dependencies - it's foundational

    def analyze(self, apk_path: str, context: AnalysisContext) -> APKOverviewResult:
        """Perform comprehensive APK overview analysis.

        Args:
            apk_path: Path to APK file
            context: Analysis context

        Returns:
            APKOverviewResult with comprehensive APK data
        """
        start_time = time.time()

        try:
            self.logger.info(f"Starting APK overview analysis for: {apk_path}")

            # Parse APK with androguard
            apk_overview = parse_apk(apk_path)
            if not apk_overview:
                return APKOverviewResult(
                    module_name="apk_overview",
                    status=AnalysisStatus.FAILURE,
                    error_message="Failed to parse APK with androguard",
                    execution_time=time.time() - start_time,
                )

            # Create app_dic structure for analyze_apk function
            base_dir, name, file_ext = split_path_file_extension(apk_path)
            app_dic = {"app_dir": Path(base_dir), "md5": apk_overview.file_md5, "app_path": apk_path}

            # Get comprehensive APK analysis
            apk_analysis = analyze_apk(apk_path, apk_overview, app_dic, permissions_details=True)

            result = APKOverviewResult(
                module_name="apk_overview",
                status=AnalysisStatus.SUCCESS,
                execution_time=time.time() - start_time,
                general_info=apk_analysis["general_info"],
                components=apk_analysis["components"],
                permissions=apk_analysis["permissions"],
                certificates=apk_analysis["certificates"],
                native_libs=apk_analysis["native_libs"],
                directory_listing=apk_analysis["directory_listing"],
                is_cross_platform=apk_analysis["is_cross_platform"],
                cross_platform_framework=apk_analysis["cross_platform_framework"],
            )

            self.logger.info(f"APK overview analysis completed successfully in {result.execution_time:.2f}s")
            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"APK overview analysis failed: {str(e)}")

            return APKOverviewResult(
                module_name="apk_overview",
                status=AnalysisStatus.FAILURE,
                error_message=str(e),
                execution_time=execution_time,
            )
