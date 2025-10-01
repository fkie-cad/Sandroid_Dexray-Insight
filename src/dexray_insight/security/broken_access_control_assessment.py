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

"""Broken Access Control Assessment.

This module implements OWASP A01:2021 - Broken Access Control vulnerability assessment.
It analyzes Android applications for access control weaknesses.
"""

import logging
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment


@register_assessment("broken_access_control")
class BrokenAccessControlAssessment(BaseSecurityAssessment):
    """OWASP A01:2021 - Broken Access Control vulnerability assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize broken access control assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A01:2021-Broken Access Control"

        self.check_exported_components = config.get("check_exported_components", True)
        self.check_permissions = config.get("check_permissions", True)

        # Dangerous permissions that may indicate access control issues
        self.dangerous_permissions = [
            "WRITE_EXTERNAL_STORAGE",
            "READ_EXTERNAL_STORAGE",
            "MANAGE_EXTERNAL_STORAGE",
            "WRITE_SETTINGS",
            "WRITE_SECURE_SETTINGS",
            "INSTALL_PACKAGES",
            "DELETE_PACKAGES",
            "READ_PHONE_STATE",
            "WRITE_SMS",
            "SEND_SMS",
            "CAMERA",
            "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "SYSTEM_ALERT_WINDOW",
            "BIND_ACCESSIBILITY_SERVICE",
            "BIND_DEVICE_ADMIN",
        ]

    def assess(self, analysis_data: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform broken access control vulnerability assessment."""
        findings = []

        try:
            if self.check_exported_components:
                findings.extend(self._assess_exported_components(analysis_data))

            if self.check_permissions:
                findings.extend(self._assess_dangerous_permissions(analysis_data))

            findings.extend(self._assess_intent_filter_risks(analysis_data))

            self.logger.info(
                f"Completed broken access control assessment. Found {len(findings)} potential issues in {self.owasp_category}"
            )

        except Exception as e:
            self.logger.error(f"Error during broken access control assessment: {e}")
            findings.append(
                SecurityFinding(
                    title="Assessment Error",
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    description="An error occurred during access control assessment",
                    evidence=[str(e)],
                )
            )

        return findings

    def _assess_exported_components(self, analysis_data: dict[str, Any]) -> list[SecurityFinding]:
        """Assess exported components for access control issues."""
        findings = []

        try:
            manifest_results = analysis_data.get("manifest_analysis", {})
            manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

            components = {
                "activities": manifest_data.get("activities", []),
                "services": manifest_data.get("services", []),
                "receivers": manifest_data.get("receivers", []),
                "content_providers": manifest_data.get("content_providers", []),
            }

            # Check for exported activities
            activities = components.get("activities", [])
            for activity in activities:
                if activity.get("exported", False):
                    if not activity.get("permission"):  # No permission protection
                        findings.append(
                            SecurityFinding(
                                title="Unprotected Exported Activity",
                                category=self.owasp_category,
                                severity=AnalysisSeverity.MEDIUM,
                                description=(
                                    f"Activity '{activity['name']}' is exported but not protected with permissions. "
                                    "This could allow unauthorized access by other applications."
                                ),
                                evidence=[f"Exported activity: {activity['name']}", "No permission protection found"],
                            )
                        )

            # Check for exported services
            services = components.get("services", [])
            for service in services:
                if service.get("exported", False):
                    if not service.get("permission"):
                        severity = (
                            AnalysisSeverity.HIGH
                            if "bind" in service.get("name", "").lower()
                            else AnalysisSeverity.MEDIUM
                        )
                        findings.append(
                            SecurityFinding(
                                title="Unprotected Exported Service",
                                category=self.owasp_category,
                                severity=severity,
                                description=(
                                    f"Service '{service['name']}' is exported but not protected with permissions. "
                                    "This could allow unauthorized binding or interaction by malicious applications."
                                ),
                                evidence=[f"Exported service: {service['name']}", "No permission protection found"],
                            )
                        )

            # Check for exported receivers
            receivers = components.get("receivers", [])
            for receiver in receivers:
                if receiver.get("exported", False):
                    if not receiver.get("permission"):
                        findings.append(
                            SecurityFinding(
                                title="Unprotected Exported Broadcast Receiver",
                                category=self.owasp_category,
                                severity=AnalysisSeverity.MEDIUM,
                                description=(
                                    f"Broadcast receiver '{receiver['name']}' is exported but not protected. "
                                    "This could allow unauthorized broadcast injection."
                                ),
                                evidence=[f"Exported receiver: {receiver['name']}", "No permission protection found"],
                            )
                        )

            # Look for potentially exported components without explicit export declaration
            potentially_exported = self._find_potentially_exported_components(components)
            for component_type, component_list in potentially_exported.items():
                for component in component_list:
                    findings.append(
                        SecurityFinding(
                            title=f"Potentially Exported {component_type.capitalize()[:-1]}",
                            category=self.owasp_category,
                            severity=AnalysisSeverity.LOW,
                            description=(
                                f"{component_type.capitalize()[:-1]} '{component['name']}' may be implicitly exported "
                                "due to intent filters without explicit export control."
                            ),
                            evidence=[
                                f"Component: {component['name']}",
                                f"Intent filters present: {len(component.get('intent_filters', []))}",
                            ],
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error assessing exported components: {e}")

        return findings

    def _find_potentially_exported_components(self, components: dict[str, list]) -> dict[str, list]:
        """Find components that might be implicitly exported due to intent filters."""
        potentially_exported = {"activities": [], "services": [], "receivers": []}

        for component_type in potentially_exported.keys():
            for component in components.get(component_type, []):
                if not component.get("exported", False):  # Not explicitly exported
                    if component.get("intent_filters") and len(component["intent_filters"]) > 0:
                        potentially_exported[component_type].append(component)

        return potentially_exported

    def _assess_dangerous_permissions(self, analysis_data: dict[str, Any]) -> list[SecurityFinding]:
        """Assess use of dangerous permissions that could indicate access control issues."""
        findings = []

        try:
            manifest_results = analysis_data.get("manifest_analysis", {})
            manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

            uses_permissions = manifest_data.get("permissions", [])

            dangerous_found = []
            for permission in uses_permissions:
                # After to_dict(), permissions are always strings
                permission_name = (
                    permission.replace("android.permission.", "") if isinstance(permission, str) else str(permission)
                )

                if permission_name in self.dangerous_permissions:
                    dangerous_found.append(permission_name)

            if dangerous_found:
                severity = (
                    AnalysisSeverity.HIGH
                    if len(dangerous_found) >= 5 or "WRITE_SECURE_SETTINGS" in dangerous_found
                    else AnalysisSeverity.MEDIUM
                )

                findings.append(
                    SecurityFinding(
                        title="Excessive Dangerous Permissions",
                        category=self.owasp_category,
                        severity=severity,
                        description=(
                            f"Application requests {len(dangerous_found)} dangerous permissions. "
                            "Ensure proper access controls are implemented to prevent privilege escalation."
                        ),
                        evidence=[f"Dangerous permissions: {', '.join(dangerous_found)}"],
                    )
                )

            # Check for custom permissions definition (not available in ManifestAnalysisResult)
            defined_permissions = []

            for perm in defined_permissions:
                protection_level = perm.get("protectionLevel", "normal")
                if protection_level in ["dangerous", "signature", "signatureOrSystem"]:
                    findings.append(
                        SecurityFinding(
                            title="Custom Dangerous Permission Defined",
                            category=self.owasp_category,
                            severity=AnalysisSeverity.MEDIUM,
                            description=(
                                f"Application defines custom permission '{perm['name']}' with protection level "
                                f"'{protection_level}'. Ensure proper access controls are enforced."
                            ),
                            evidence=[f"Permission: {perm['name']}", f"Protection level: {protection_level}"],
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error assessing dangerous permissions: {e}")

        return findings

    def _assess_intent_filter_risks(self, analysis_data: dict[str, Any]) -> list[SecurityFinding]:
        """Assess intent filter configurations for access control risks."""
        findings = []

        try:
            manifest_results = analysis_data.get("manifest_analysis", {})
            manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

            # Get intent filters from manifest data
            intent_filters = manifest_data.get("intent_filters", [])

            for intent_filter in intent_filters:
                if self._is_risky_intent_filter(intent_filter):
                    findings.append(
                        SecurityFinding(
                            title="Risky Intent Filter Configuration",
                            category=self.owasp_category,
                            severity=AnalysisSeverity.MEDIUM,
                            description="Intent filter configuration detected that may allow unauthorized access.",
                            evidence=[
                                f"Actions: {', '.join(intent_filter.get('actions', []))}",
                                f"Categories: {', '.join(intent_filter.get('categories', []))}",
                            ],
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error assessing intent filter risks: {e}")

        return findings

    def _is_risky_intent_filter(self, intent_filter: dict[str, Any]) -> bool:
        """Check if an intent filter configuration poses access control risks."""
        risky_actions = [
            "android.intent.action.VIEW",
            "android.intent.action.EDIT",
            "android.intent.action.DELETE",
            "android.intent.action.INSERT",
            "android.intent.action.SEND",
            "android.intent.action.SENDTO",
            "android.intent.action.SEND_MULTIPLE",
            "android.intent.action.GET_CONTENT",
            "android.intent.action.PICK",
        ]

        risky_categories = [
            "android.intent.category.DEFAULT",
            "android.intent.category.BROWSABLE",
        ]

        actions = intent_filter.get("actions", [])
        categories = intent_filter.get("categories", [])

        # Check for risky action/category combinations
        has_risky_action = any(action in risky_actions for action in actions)
        has_default_category = "android.intent.category.DEFAULT" in categories
        has_browsable_category = "android.intent.category.BROWSABLE" in categories

        # Particularly risky: browsable activities that can handle various actions
        if has_browsable_category and has_risky_action:
            return True

        # Also risky: default handlers for sensitive actions
        if has_default_category and has_risky_action:
            return True

        return False
