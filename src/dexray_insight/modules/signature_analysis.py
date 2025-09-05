#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Digital signature analysis module for APK certificate verification."""

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

import time
from dataclasses import dataclass
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisStatus
from ..core.base_classes import BaseAnalysisModule
from ..core.base_classes import BaseResult
from ..core.base_classes import register_module
from ..signature_detection.hash import get_sha256_hash_of_apk
from ..signature_detection.koodous import koodous_hash_check
from ..signature_detection.triage import triage_hashcheck
from ..signature_detection.vt import vt_check_file_reputation


@dataclass
class SignatureAnalysisResult(BaseResult):
    """Result class for signature analysis."""

    signatures: dict[str, Any] = None
    apk_hash: str = ""
    providers_checked: list[str] = None

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.signatures is None:
            self.signatures = {}
        if self.providers_checked is None:
            self.providers_checked = []

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        base_dict = super().to_dict()
        base_dict.update(
            {"signatures": self.signatures, "apk_hash": self.apk_hash, "providers_checked": self.providers_checked}
        )
        return base_dict


@register_module("signature_detection")
class SignatureAnalysisModule(BaseAnalysisModule):
    """Signature detection and hash-based analysis module."""

    def __init__(self, config: dict[str, Any]):
        """Initialize SignatureAnalysisModule with configuration."""
        super().__init__(config)
        self.providers = config.get("providers", {})

    def get_dependencies(self) -> list[str]:
        """No dependencies for signature analysis."""
        return []

    def analyze(self, apk_path: str, context: AnalysisContext) -> SignatureAnalysisResult:
        """
        Perform signature analysis on the APK.

        Args:
            apk_path: Path to the APK file
            context: Analysis context

        Returns:
            SignatureAnalysisResult with analysis results
        """
        start_time = time.time()

        try:
            # Get SHA256 hash of the APK
            apk_hash = get_sha256_hash_of_apk(apk_path)

            signatures = {}
            providers_checked = []

            # Check each enabled provider
            if self.providers.get("koodous", {}).get("enabled", False):
                try:
                    signatures["koodous"] = koodous_hash_check(apk_hash, context.config)
                    providers_checked.append("koodous")
                except Exception as e:
                    self.logger.error(f"Koodous check failed: {str(e)}")
                    signatures["koodous"] = None

            if self.providers.get("virustotal", {}).get("enabled", False):
                try:
                    signatures["vt"] = vt_check_file_reputation(apk_hash, context.config)
                    providers_checked.append("virustotal")
                except Exception as e:
                    self.logger.error(f"VirusTotal check failed: {str(e)}")
                    signatures["vt"] = None

            if self.providers.get("triage", {}).get("enabled", False):
                try:
                    signatures["triage"] = triage_hashcheck(apk_hash, context.config)
                    providers_checked.append("triage")
                except Exception as e:
                    self.logger.error(f"Triage check failed: {str(e)}")
                    signatures["triage"] = None

            execution_time = time.time() - start_time

            return SignatureAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                signatures=signatures,
                apk_hash=apk_hash,
                providers_checked=providers_checked,
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return SignatureAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                signatures={},
                apk_hash="",
                providers_checked=[],
            )

    def validate_config(self) -> bool:
        """Validate module configuration."""
        # Check if at least one provider is enabled
        if not any(provider.get("enabled", False) for provider in self.providers.values()):
            return False

        # Check API keys for enabled providers
        for provider_name, provider_config in self.providers.items():
            if provider_config.get("enabled", False):
                api_key = provider_config.get("api_key")
                if provider_name in ["virustotal", "koodous"] and not api_key:
                    self.logger.warning(f"{provider_name} is enabled but no API key provided")

        return True
