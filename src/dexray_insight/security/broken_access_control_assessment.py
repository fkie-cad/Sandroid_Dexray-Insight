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
from .evidence import carries_browsable_or_custom_scheme
from .evidence import classify_component
from .evidence import should_downrank  # noqa: F401  (public helper; used by callers/tests)


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

        # First-party package prefixes let the exported-component triage treat the
        # app's own code as first-party even when it is namespaced unusually. Read
        # defensively from this assessment's own config (never from dexray.yaml
        # directly). Accepts a list under either key for forward compatibility.
        configured_prefixes = config.get("first_party_prefixes") or config.get("first_party_packages") or []
        self.first_party_prefixes = [str(p) for p in configured_prefixes if p] if isinstance(configured_prefixes, (list, tuple)) else []

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

        # Standard dangerous permissions that are commonly justified by an app's
        # core functionality (a messenger with camera/mic/contacts, a gallery app,
        # a maps app, ...). These are legitimately worth *noting* but declaring them
        # is not, on its own, a HIGH risk -- rating a routine set HIGH inflates the
        # headline. They map to a LOW / informational finding regardless of count.
        self.commonly_justified_permissions = {
            "CAMERA",
            "RECORD_AUDIO",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "READ_CONTACTS",
            "GET_ACCOUNTS",
        }
        # READ_MEDIA_IMAGES / READ_MEDIA_VIDEO / READ_MEDIA_AUDIO / READ_MEDIA_VISUAL_USER_SELECTED
        # are the Android 13+ scoped replacements for storage reads and are equally routine.
        self.commonly_justified_permission_prefixes = ("READ_MEDIA_",)

        # Rarely-justified over-grants: signature/system-level permissions or ones
        # that hand an app broad control over the device or other apps. Any one of
        # these present raises the finding to HIGH regardless of the rest of the set.
        self.high_risk_permissions = {
            "WRITE_SECURE_SETTINGS",
            "INSTALL_PACKAGES",
            "DELETE_PACKAGES",
            "BIND_DEVICE_ADMIN",
            "BIND_ACCESSIBILITY_SERVICE",
        }
        # Elevated-but-not-critical permissions that are more often abused than the
        # routine set and warrant a MEDIUM when present without a HIGH over-grant.
        self.elevated_risk_permissions = {
            "MANAGE_EXTERNAL_STORAGE",
            "WRITE_SETTINGS",
            "WRITE_SMS",
            "SEND_SMS",
            "SYSTEM_ALERT_WINDOW",
            "READ_PHONE_STATE",
        }

    def assess(self, analysis_data: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform broken access control vulnerability assessment."""
        findings = []

        try:
            if self.check_exported_components:
                findings.extend(self._assess_exported_components(analysis_data))

            if self.check_permissions:
                findings.extend(self._assess_dangerous_permissions(analysis_data))

            findings.extend(self._assess_intent_filter_risks(analysis_data))

            findings.extend(self._assess_exported_deeplink_activities(analysis_data))

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
                    recommendations=["Review analysis logs and re-run the assessment"],
                )
            )

        return findings

    @staticmethod
    def _component_name(component: Any) -> str:
        """Return a component's class name whether it is a dict or a plain string.

        ManifestAnalysisResult stores components as plain name strings, but this
        assessment is written against a richer dict shape. This accessor bridges
        both so the assessment never crashes on the string form.
        """
        if isinstance(component, dict):
            return component.get("name", "")
        return str(component)

    @staticmethod
    def _build_intent_filter_index(manifest_data: dict[str, Any]) -> dict[str, list]:
        """Index intent-filter entries by component name.

        Manifest intent_filters entries have the shape
        ``{"component_type", "component_name", "filters"}`` (see
        manifest_analysis._extract_intent_filters). Only services and receivers
        carry intent filters upstream; activities are not indexed.
        """
        index: dict[str, list] = {}
        for entry in manifest_data.get("intent_filters", []) or []:
            if isinstance(entry, dict):
                name = entry.get("component_name")
                if name is not None:
                    index.setdefault(name, []).append(entry)
        return index

    def _normalize_component(self, component: Any, intent_index: dict[str, list]) -> dict[str, Any]:
        """Normalize a component (dict or name-string) to a canonical dict.

        For the name-only data actually produced today, export/permission
        metadata is unknown (``None``) so the explicit-export checks safely
        produce no findings, while intent-filter-based detection still works via
        the intent_index.
        """
        if isinstance(component, dict):
            # Ensure intent_filters is present so downstream .get calls are safe.
            if "intent_filters" not in component:
                component = {
                    **component,
                    "intent_filters": intent_index.get(component.get("name"), []),
                }
            return component
        name = str(component)
        return {
            "name": name,
            "exported": None,
            "permission": None,
            "intent_filters": intent_index.get(name, []),
        }

    def _assess_exported_components(self, analysis_data: dict[str, Any]) -> list[SecurityFinding]:
        """Assess exported components for access control issues."""
        findings = []

        try:
            manifest_results = analysis_data.get("manifest_analysis", {})
            manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

            intent_index = self._build_intent_filter_index(manifest_data)

            def _normalize_list(key: str) -> list[dict[str, Any]]:
                return [self._normalize_component(c, intent_index) for c in manifest_data.get(key, []) or []]

            components = {
                "activities": _normalize_list("activities"),
                "services": _normalize_list("services"),
                "receivers": _normalize_list("receivers"),
                "content_providers": _normalize_list("content_providers"),
            }

            ctx = self._build_triage_ctx(analysis_data)

            findings.extend(self._assess_exported_activities(components, ctx))
            findings.extend(self._assess_exported_services(components, ctx))
            findings.extend(self._assess_exported_receivers(components, ctx))
            findings.extend(self._assess_potentially_exported_components(components, ctx))

        except Exception as e:
            self.logger.error(f"Error assessing exported components: {e}")

        return findings

    @staticmethod
    def _extract_package_name(analysis_data: dict[str, Any]) -> str | None:
        """Read the app package name from apk_overview.general_info defensively.

        apk_overview may be a dataclass/object or a dict, and general_info may be
        nested as an attribute or key. Any shape we do not understand yields None
        so the triage falls back to prefix/library classification only.
        """
        overview = analysis_data.get("apk_overview")
        if overview is None:
            return None
        general = getattr(overview, "general_info", None)
        if general is None and isinstance(overview, dict):
            general = overview.get("general_info")
        if general is None:
            return None
        pkg = getattr(general, "package_name", None)
        if pkg is None and isinstance(general, dict):
            pkg = general.get("package_name")
        return str(pkg) if pkg else None

    def _build_triage_ctx(self, analysis_data: dict[str, Any]) -> dict[str, Any]:
        """Assemble the context used to classify exported components."""
        return {
            "package_name": self._extract_package_name(analysis_data),
            "first_party_prefixes": self.first_party_prefixes,
            "library_results": analysis_data.get("library_detection") or analysis_data.get("library_analysis"),
        }

    def _triage(
        self,
        component: dict[str, Any],
        ctx: dict[str, Any],
        base_severity: AnalysisSeverity,
        has_permission: bool = False,
    ) -> tuple[AnalysisSeverity, float, str]:
        """Return (severity, confidence, classification) for an exported component.

        Applies the package-allowlist down-rank: framework-owned components drop
        to LOW/low-confidence, but a component that is a deep-link entry point
        (BROWSABLE / custom URI scheme) is ALWAYS surfaced regardless of its
        package name (repackaging can spoof a ``com.google.*`` name). A
        permission-guarded component is down-ranked (protected) rather than
        dropped.
        """
        name = self._component_name(component)
        classification = classify_component(
            name,
            package_name=ctx.get("package_name"),
            first_party_prefixes=ctx.get("first_party_prefixes"),
            library_results=ctx.get("library_results"),
        )
        browsable = carries_browsable_or_custom_scheme(component.get("intent_filters"))

        if has_permission:
            # Protected by a permission: keep as a low-confidence posture note.
            return AnalysisSeverity.LOW, 0.25, classification
        if browsable:
            # Externally reachable deep-link entry point: always surfaced.
            return base_severity, 0.6, classification
        if should_downrank(classification):  # framework, no deep link
            return AnalysisSeverity.LOW, 0.25, classification
        if classification == "first_party":
            return base_severity, 0.6, classification
        # unknown / third-party-but-not-allowlisted
        return base_severity, 0.5, classification

    def _assess_exported_activities(self, components: dict[str, list], ctx: dict[str, Any] | None = None) -> list[SecurityFinding]:
        """Assess exported activities for missing permission protection."""
        findings = []

        ctx = ctx or {}

        # Check for exported activities
        activities = components.get("activities", [])
        for activity in activities:
            if activity.get("exported", False) and not activity.get("permission"):  # No permission protection
                name = self._component_name(activity)
                severity, confidence, classification = self._triage(activity, ctx, AnalysisSeverity.MEDIUM)
                findings.append(
                        SecurityFinding(
                            title="Unprotected Exported Activity",
                            category=self.owasp_category,
                            severity=severity,
                            confidence=confidence,
                            description=(
                                f"Activity '{name}' is exported but not protected with permissions. "
                                "This could allow unauthorized access by other applications."
                            ),
                            evidence=[
                                f"Exported activity: {name}",
                                "No permission protection found",
                                f"Component classification: {classification}",
                            ],
                            recommendations=[
                                "Set android:exported=\"false\" unless the component must be public",
                                "Protect exported components with signature-level permissions",
                                "Validate all incoming Intent data",
                            ],
                        )
                    )

        return findings

    def _assess_exported_services(self, components: dict[str, list], ctx: dict[str, Any] | None = None) -> list[SecurityFinding]:
        """Assess exported services for missing permission protection."""
        findings = []

        ctx = ctx or {}

        # Check for exported services
        services = components.get("services", [])
        for service in services:
            if service.get("exported", False) and not service.get("permission"):
                name = self._component_name(service)
                base_severity = (
                    AnalysisSeverity.HIGH
                    if "bind" in name.lower()
                    else AnalysisSeverity.MEDIUM
                )
                severity, confidence, classification = self._triage(service, ctx, base_severity)
                findings.append(
                    SecurityFinding(
                        title="Unprotected Exported Service",
                        category=self.owasp_category,
                        severity=severity,
                        confidence=confidence,
                        description=(
                            f"Service '{name}' is exported but not protected with permissions. "
                            "This could allow unauthorized binding or interaction by malicious applications."
                        ),
                        evidence=[
                            f"Exported service: {name}",
                            "No permission protection found",
                            f"Component classification: {classification}",
                        ],
                        recommendations=[
                            "Set android:exported=\"false\" unless the service must be public",
                            "Protect exported services with signature-level permissions",
                            "Validate all incoming Intent data before acting on it",
                        ],
                    )
                )

        return findings

    def _assess_exported_receivers(self, components: dict[str, list], ctx: dict[str, Any] | None = None) -> list[SecurityFinding]:
        """Assess exported broadcast receivers for missing permission protection."""
        findings = []

        ctx = ctx or {}

        # Check for exported receivers
        receivers = components.get("receivers", [])
        for receiver in receivers:
            if receiver.get("exported", False) and not receiver.get("permission"):
                name = self._component_name(receiver)
                severity, confidence, classification = self._triage(receiver, ctx, AnalysisSeverity.MEDIUM)
                findings.append(
                    SecurityFinding(
                        title="Unprotected Exported Broadcast Receiver",
                        category=self.owasp_category,
                        severity=severity,
                        confidence=confidence,
                        description=(
                            f"Broadcast receiver '{name}' is exported but not protected. "
                            "This could allow unauthorized broadcast injection."
                        ),
                        evidence=[
                            f"Exported receiver: {name}",
                            "No permission protection found",
                            f"Component classification: {classification}",
                        ],
                        recommendations=[
                            "Set android:exported=\"false\" unless the receiver must be public",
                            "Protect exported receivers with signature-level permissions",
                            "Validate the source and contents of received broadcasts",
                        ],
                    )
                )

        return findings

    def _assess_potentially_exported_components(self, components: dict[str, list], ctx: dict[str, Any] | None = None) -> list[SecurityFinding]:
        """Assess components potentially exported via intent filters without explicit declaration."""
        findings = []

        ctx = ctx or {}

        # Look for potentially exported components without explicit export declaration
        potentially_exported = self._find_potentially_exported_components(components)
        for component_type, component_list in potentially_exported.items():
            for component in component_list:
                name = self._component_name(component)
                has_permission = bool(component.get("permission"))
                severity, confidence, classification = self._triage(
                    component, ctx, AnalysisSeverity.MEDIUM, has_permission=has_permission
                )
                evidence = [
                    f"Component: {name}",
                    f"Intent filters present: {len(component.get('intent_filters', []))}",
                    f"Component classification: {classification}",
                ]
                if has_permission:
                    evidence.append(f"Permission guard present: {component.get('permission')}")
                if carries_browsable_or_custom_scheme(component.get("intent_filters")):
                    evidence.append("Exposes a deep-link entry point (BROWSABLE or custom URI scheme)")
                findings.append(
                    SecurityFinding(
                        title=f"Potentially Exported {component_type.capitalize()[:-1]}",
                        category=self.owasp_category,
                        severity=severity,
                        confidence=confidence,
                        description=(
                            f"{component_type.capitalize()[:-1]} '{name}' may be implicitly exported "
                            "due to intent filters without explicit export control."
                        ),
                        evidence=evidence,
                        recommendations=[
                            "Explicitly set android:exported for components with intent filters",
                            "Add permission guards to components reachable via intent filters",
                            "Use explicit intents internally where possible",
                        ],
                    )
                )

        return findings

    def _find_potentially_exported_components(self, components: dict[str, list]) -> dict[str, list]:
        """Find components that might be implicitly exported due to intent filters.

        A component is a candidate when it has at least one intent filter and is
        NOT explicitly declared ``android:exported="false"``. Explicitly
        non-exported components cannot be reached externally, so they are skipped
        entirely (they previously flooded the report - e.g. 4 of Kik's exported
        "findings" were ``exported="false"`` services). Permission-guarded and
        framework-owned candidates are still returned here but are down-ranked in
        :meth:`_assess_potentially_exported_components`.
        """
        potentially_exported = {"activities": [], "services": [], "receivers": []}

        for component_type in potentially_exported:
            for component in components.get(component_type, []):
                intent_filters = component.get("intent_filters")
                if not intent_filters or len(intent_filters) == 0:
                    continue
                # Only components WITHOUT an explicit export declaration belong here.
                # exported=True is handled by the explicit-export paths above;
                # exported=False cannot be reached externally, so both are skipped.
                if component.get("exported") is not None:
                    continue
                potentially_exported[component_type].append(component)

        return potentially_exported

    def _is_commonly_justified_permission(self, permission_name: str) -> bool:
        """Return True for standard dangerous permissions routinely justified by app features.

        These map to a LOW / informational finding regardless of how many are
        present, so a normal messenger/gallery/maps permission set does not inflate
        the headline severity.
        """
        if permission_name in self.commonly_justified_permissions:
            return True
        return any(permission_name.startswith(prefix) for prefix in self.commonly_justified_permission_prefixes)

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
                # Severity is driven by *which* permissions are present, not by the
                # raw count. A large-but-routine set (messenger with camera, mic,
                # contacts, location, storage) is LOW/informational; only rarely
                # justified over-grants escalate the finding.
                over_grants = [p for p in dangerous_found if p in self.high_risk_permissions]
                elevated = [p for p in dangerous_found if p in self.elevated_risk_permissions]
                # Anything left that is neither a known over-grant nor part of the
                # commonly-justified standard set is treated conservatively (MEDIUM).
                unrecognized = [
                    p
                    for p in dangerous_found
                    if p not in self.high_risk_permissions
                    and p not in self.elevated_risk_permissions
                    and not self._is_commonly_justified_permission(p)
                ]

                if over_grants:
                    severity = AnalysisSeverity.HIGH
                    description = (
                        f"Application requests {len(dangerous_found)} dangerous permissions, including "
                        f"rarely-justified over-grants ({', '.join(over_grants)}). These grant broad "
                        "control over the device or other apps and enable privilege escalation if abused."
                    )
                elif elevated or unrecognized:
                    severity = AnalysisSeverity.MEDIUM
                    flagged = elevated + unrecognized
                    description = (
                        f"Application requests {len(dangerous_found)} dangerous permissions, including "
                        f"elevated-risk permissions ({', '.join(flagged)}). Ensure proper access controls "
                        "are enforced and each is justified by the app's functionality."
                    )
                else:
                    # Only permissions from the commonly-justified standard set.
                    severity = AnalysisSeverity.LOW
                    description = (
                        f"Application declares {len(dangerous_found)} standard dangerous permissions. "
                        "These are commonly justified by core functionality (camera, microphone, "
                        "contacts, location, media/storage) and are worth noting, but declaring them "
                        "is not on its own a high-risk condition."
                    )

                findings.append(
                    SecurityFinding(
                        title="Excessive Dangerous Permissions",
                        category=self.owasp_category,
                        severity=severity,
                        description=description,
                        evidence=[f"Dangerous permissions: {', '.join(dangerous_found)}"],
                        recommendations=[
                            "Request only the minimum permissions required by the app",
                            "Justify each dangerous permission and enforce runtime permission checks",
                            "Avoid signature/system permissions unless strictly necessary",
                        ],
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
                            recommendations=[
                                "Use the highest appropriate protection level for custom permissions",
                                "Document why each custom permission is required",
                                "Enforce the permission on every component it is meant to guard",
                            ],
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
                    actions, categories = self._intent_filter_actions_categories(intent_filter)
                    component_name = (
                        intent_filter.get("component_name", "") if isinstance(intent_filter, dict) else ""
                    )
                    findings.append(
                        SecurityFinding(
                            title="Risky Intent Filter Configuration",
                            category=self.owasp_category,
                            severity=AnalysisSeverity.MEDIUM,
                            description="Intent filter configuration detected that may allow unauthorized access.",
                            evidence=[
                                f"Component: {component_name}" if component_name else "Component: (unknown)",
                                f"Actions: {', '.join(actions)}",
                                f"Categories: {', '.join(categories)}",
                            ],
                            recommendations=[
                                "Use explicit intents where possible",
                                "Add android:exported and permission guards to components with intent filters",
                                "Validate action/category/data before handling the intent",
                            ],
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error assessing intent filter risks: {e}")

        return findings

    @staticmethod
    def _intent_filter_actions_categories(intent_filter: Any) -> tuple[list, list]:
        """Extract (actions, categories) from an intent-filter entry.

        Handles both the manifest shape
        ``{"component_type", "component_name", "filters": {"action": [...], "category": [...]}}``
        and a flat legacy shape with top-level ``actions``/``categories``.
        """
        if not isinstance(intent_filter, dict):
            return [], []
        filters = intent_filter.get("filters")
        if isinstance(filters, dict):
            actions = filters.get("action", filters.get("actions", []))
            categories = filters.get("category", filters.get("categories", []))
        else:
            actions = intent_filter.get("actions", [])
            categories = intent_filter.get("categories", [])
        # Normalize to lists of strings.
        actions = list(actions) if actions else []
        categories = list(categories) if categories else []
        return actions, categories

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

        _risky_categories = [
            "android.intent.category.DEFAULT",
            "android.intent.category.BROWSABLE",
        ]

        actions, categories = self._intent_filter_actions_categories(intent_filter)

        # Check for risky action/category combinations
        has_risky_action = any(action in risky_actions for action in actions)
        has_default_category = "android.intent.category.DEFAULT" in categories
        has_browsable_category = "android.intent.category.BROWSABLE" in categories

        # Particularly risky: browsable activities that can handle various actions
        if has_browsable_category and has_risky_action:
            return True

        # Also risky: default handlers for sensitive actions
        return bool(has_default_category and has_risky_action)

    # ------------------------------------------------------------------ #
    # Deep-link / browsable exported activity detection (IPC attack surface)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_apk_overview_dict(analysis_data: dict[str, Any]) -> dict[str, Any] | None:
        """Return a plain-dict view of the apk_overview result, or None.

        apk_overview may be a dataclass exposing ``to_dict()``, a raw dict, or
        absent. Any shape we do not understand yields None so detection is a
        no-op rather than crashing.
        """
        overview = analysis_data.get("apk_overview")
        if overview is None:
            return None
        if isinstance(overview, dict):
            return overview
        to_dict = getattr(overview, "to_dict", None)
        if callable(to_dict):
            try:
                return to_dict()
            except Exception:
                return None
        return None

    @staticmethod
    def _deeplink_exported_names(overview: dict[str, Any]) -> set[str]:
        """Collect the set of exported activity name strings from apk_overview."""
        names: set[str] = set()
        components = overview.get("components")
        if isinstance(components, dict):
            for entry in components.get("exported_activities") or []:
                if isinstance(entry, dict):
                    entry = entry.get("name")
                if entry:
                    names.add(str(entry))
        return names

    @staticmethod
    def _deeplink_is_exported(name: str, data: dict[str, Any], exported_names: set[str]) -> bool:
        """Decide whether a browsable activity is externally reachable.

        An explicit ``exported`` flag on the entry wins; otherwise the activity
        is treated as exported only when its name appears in apk_overview's
        exported-activity list. A browsable activity that is not exported cannot
        be reached from another app, so it is skipped.
        """
        exported = data.get("exported")
        if exported is False:
            return False
        if exported is True:
            return True
        return name in exported_names

    @staticmethod
    def _deeplink_schemes(data: dict[str, Any]) -> list[str]:
        """Return the declared URI schemes for a browsable-activity entry."""
        schemes = data.get("schemes")
        if isinstance(schemes, (list, tuple)):
            return [str(s) for s in schemes if s]
        if isinstance(schemes, str) and schemes:
            return [schemes]
        return []

    @staticmethod
    def _deeplink_filters_view(data: dict[str, Any]) -> dict[str, Any]:
        """Build an intent-filter-shaped view for ``carries_browsable_or_custom_scheme``.

        Entries in apk_overview.browsable_activities are browsable by
        construction, so BROWSABLE is always present; schemes are forwarded so
        the custom-scheme spoof-resistance override applies uniformly.
        """
        categories = data.get("categories") or ["android.intent.category.BROWSABLE"]
        return {
            "filters": {
                "category": categories,
                "scheme": BrokenAccessControlAssessment._deeplink_schemes(data),
            }
        }

    @staticmethod
    def _is_custom_scheme(scheme: str) -> bool:
        """Return True when a scheme (e.g. ``kik://``) is a non-standard URI scheme."""
        token = scheme.strip().rstrip(":/").lower()
        standard = {"http", "https", "content", "file", "tel", "mailto", "sms", "smsto", "geo", "market"}
        return bool(token) and token not in standard

    def _assess_exported_deeplink_activities(self, analysis_data: dict[str, Any]) -> list[SecurityFinding]:
        """Detect exported browsable/deep-link activities that lack permission protection.

        Cross-references apk_overview.browsable_activities (per-activity deep-link
        metadata) with the exported-activity list. Each exported, unprotected
        deep-link entry point is surfaced. Severity/confidence follow the
        package-allowlist classification (first-party -> MEDIUM/0.7, framework ->
        LOW/0.3), but deep-link entry points are NEVER dropped by the allowlist
        (spoof resistance via ``carries_browsable_or_custom_scheme``). Catch-all
        VIEW+BROWSABLE filters (no ``<data>`` scheme) and custom URI schemes
        escalate the description.
        """
        findings: list[SecurityFinding] = []

        try:
            overview = self._extract_apk_overview_dict(analysis_data)
            if not overview:
                return findings

            browsable = overview.get("browsable_activities")
            if not isinstance(browsable, dict) or not browsable:
                return findings

            exported_names = self._deeplink_exported_names(overview)
            ctx = self._build_triage_ctx(analysis_data)

            for name, raw in browsable.items():
                data = raw if isinstance(raw, dict) else {}
                if not self._deeplink_is_exported(str(name), data, exported_names):
                    continue

                finding = self._build_deeplink_finding(str(name), data, ctx)
                if finding is not None:
                    findings.append(finding)

        except Exception as e:
            self.logger.error(f"Error assessing exported deep-link activities: {e}")

        return findings

    def _build_deeplink_finding(
        self, name: str, data: dict[str, Any], ctx: dict[str, Any]
    ) -> SecurityFinding | None:
        """Construct the finding for a single exported deep-link activity."""
        permission = data.get("permission")
        schemes = self._deeplink_schemes(data)
        hosts = [str(h) for h in (data.get("hosts") or []) if h]
        paths = [str(p) for p in (data.get("paths") or []) if p]
        filters_view = self._deeplink_filters_view(data)

        # Spoof resistance: a deep-link entry point is always surfaced, even when
        # its package name would otherwise be down-ranked as framework.
        is_deeplink = carries_browsable_or_custom_scheme(filters_view)

        classification = classify_component(
            name,
            package_name=ctx.get("package_name"),
            first_party_prefixes=ctx.get("first_party_prefixes"),
            library_results=ctx.get("library_results"),
        )

        catch_all = not schemes  # VIEW+BROWSABLE with no <data> scheme
        custom_schemes = [s for s in schemes if self._is_custom_scheme(s)]

        if permission:
            # Protected by a permission: keep as a low-confidence posture note.
            severity, confidence = AnalysisSeverity.LOW, 0.3
        elif classification == "first_party":
            severity, confidence = AnalysisSeverity.MEDIUM, 0.7
        elif classification == "framework":
            # Down-ranked but still surfaced (never suppressed) because it is a
            # deep-link entry point that repackaging could have spoofed.
            severity, confidence = AnalysisSeverity.LOW, 0.3
        else:
            severity, confidence = AnalysisSeverity.MEDIUM, 0.5

        description = (
            f"Exported activity '{name}' is a deep-link entry point reachable by other "
            "applications or the browser without permission protection. Unvalidated deep-link "
            "input can drive unintended navigation or actions inside the app."
        )
        if catch_all:
            description += (
                " It uses a catch-all VIEW+BROWSABLE intent filter with no <data> scheme, so it "
                "will handle arbitrary deep links."
            )
        if custom_schemes:
            description += f" It registers custom URI scheme(s): {', '.join(custom_schemes)}."

        evidence = [
            f"Exported deep-link activity: {name}",
            f"Component classification: {classification}",
        ]
        evidence.append(f"URI schemes: {', '.join(schemes)}" if schemes else "URI schemes: (none - catch-all filter)")
        if hosts:
            evidence.append(f"Hosts: {', '.join(hosts)}")
        if paths:
            evidence.append(f"Paths: {', '.join(paths)}")
        if catch_all:
            evidence.append("Catch-all VIEW+BROWSABLE intent filter with no <data> scheme")
        if custom_schemes:
            evidence.append(f"Custom URI scheme(s): {', '.join(custom_schemes)}")
        if permission:
            evidence.append(f"Permission guard present: {permission}")
        if is_deeplink:
            evidence.append("Deep-link entry point (always surfaced regardless of package allowlist)")

        return SecurityFinding(
            title="Exported Deep-Link Activity Without Permission Protection",
            category=self.owasp_category,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendations=[
                "Set android:exported=\"false\" if the activity does not need to handle external deep links",
                "Protect the activity with a signature-level permission where external access is required",
                "Rigorously validate and sanitize all deep-link URI data before acting on it",
                "Avoid catch-all VIEW+BROWSABLE filters; scope intent filters to specific schemes/hosts/paths",
            ],
        )
