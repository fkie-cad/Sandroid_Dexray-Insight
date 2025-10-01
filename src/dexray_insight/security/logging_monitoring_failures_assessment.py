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

"""Logging and Monitoring Failures Assessment.

This module implements OWASP A09:2021 - Security Logging and Monitoring Failures assessment.
It identifies security logging deficiencies and monitoring gaps in Android applications.
"""

import logging
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment


@register_assessment("logging_monitoring_failures")
class LoggingMonitoringFailuresAssessment(BaseSecurityAssessment):
    """OWASP A09:2021 - Security Logging and Monitoring Failures assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize logging and monitoring failures assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A09:2021-Security Logging and Monitoring Failures"

        self.logging_patterns = [
            r"Log\.[dwiev]\([^,]+,.*(?:password|token|secret|credential|key)",
            r"System\.out\.println.*(?:password|token|secret|auth)",
            r"printStackTrace\(\)",
            r"Log\.d\([^,]+,.*(?:user|email|phone|address)",
            r"android\.util\.Log",
        ]

        self.sensitive_data_patterns = [
            "password",
            "token",
            "secret",
            "credential",
            "key",
            "email",
            "phone",
            "address",
            "ssn",
            "credit",
        ]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform logging and monitoring failures assessment."""
        findings = []

        try:
            string_results = analysis_results.get("string_analysis", {})
            if hasattr(string_results, "to_dict"):
                string_data = string_results.to_dict()
            else:
                string_data = string_results

            all_strings = string_data.get("all_strings", [])

            # Check for sensitive data logging
            sensitive_logs = []
            debug_logs = []

            for string in all_strings:
                if isinstance(string, str):
                    # Check for sensitive data in logs
                    for pattern in self.sensitive_data_patterns:
                        if pattern.lower() in string.lower():
                            if any(log_keyword in string.lower() for log_keyword in ["log.", "system.out", "print"]):
                                sensitive_logs.append(f"Sensitive data in logs: {string[:80]}...")
                                break

                    # Check for debug logging patterns
                    if any(debug_pattern in string.lower() for debug_pattern in ["log.d", "log.v", "debug", "trace"]):
                        debug_logs.append(f"Debug logging detected: {string[:60]}...")

            # Create findings based on detected issues
            if sensitive_logs:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.HIGH,
                        title="Sensitive Data Logging",
                        description="Application logs sensitive information that could be exposed to unauthorized parties.",
                        evidence=sensitive_logs[:10],  # Limit evidence items
                        recommendations=[
                            "Remove sensitive data from log statements",
                            "Use conditional logging based on build configuration",
                            "Implement secure logging practices with data sanitization",
                            "Review log outputs before production releases",
                            "Use structured logging to control data exposure",
                        ],
                    )
                )

            if len(debug_logs) > 10:  # Excessive debug logging
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.MEDIUM,
                        title="Excessive Debug Logging",
                        description="Application contains extensive debug logging that may leak internal information.",
                        evidence=debug_logs[:8],  # Sample of debug logs
                        recommendations=[
                            "Disable debug logging in production builds",
                            "Use ProGuard/R8 to remove debug code",
                            "Implement logging levels appropriate for production",
                            "Review log statements for information disclosure",
                            "Use build-time constants to control logging verbosity",
                        ],
                    )
                )

            # Check manifest for logging permissions and configurations
            manifest_results = analysis_results.get("manifest_analysis", {})
            if hasattr(manifest_results, "to_dict"):
                manifest_data = manifest_results.to_dict()
            else:
                manifest_data = manifest_results

            permissions = manifest_data.get("permissions", [])

            # Check for monitoring-related permissions
            monitoring_permissions = [
                perm
                for perm in permissions
                if any(mon_perm in perm.upper() for mon_perm in ["LOG", "DEBUG", "SYSTEM_ALERT", "DEVICE_ADMIN"])
            ]

            if not monitoring_permissions:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.LOW,
                        title="Limited Security Monitoring Capabilities",
                        description="Application may lack adequate security monitoring and alerting capabilities.",
                        evidence=["No security monitoring permissions detected"],
                        recommendations=[
                            "Implement security event logging for critical operations",
                            "Add monitoring for authentication failures and suspicious activities",
                            "Consider implementing tamper detection and alerting",
                            "Log security-relevant events with appropriate detail",
                            "Implement centralized logging for security events",
                        ],
                    )
                )

        except Exception as e:
            self.logger.error(f"Logging and monitoring failures assessment failed: {str(e)}")
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title="Assessment Error",
                    description="An error occurred during logging and monitoring assessment",
                    evidence=[str(e)],
                    recommendations=["Review application logging configuration manually"],
                )
            )

        return findings
