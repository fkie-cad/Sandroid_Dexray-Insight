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

"""Injection Assessment.

This module implements OWASP A03:2021 - Injection vulnerability assessment.
It identifies various injection vulnerabilities in Android applications.
"""

import logging
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment


@register_assessment("injection")
class InjectionAssessment(BaseSecurityAssessment):
    """OWASP A03:2021 - Injection vulnerability assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize injection assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A03:2021-Injection"

        # SQL injection patterns
        self.sql_patterns = config.get(
            "sql_patterns",
            ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "UNION", "TRUNCATE", "MERGE"],
        )

        # Command injection patterns
        self.command_patterns = config.get(
            "command_patterns", ["exec", "system", "runtime", "sh", "bash", "cmd", "powershell"]
        )

        # LDAP injection patterns
        self.ldap_patterns = ["ldap://", "ldaps://", "ldapQuery", "DirectorySearcher"]

        # NoSQL injection patterns
        self.nosql_patterns = ["$where", "$ne", "$gt", "$lt", "$regex", "find(", "aggregate("]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Assess for injection vulnerabilities."""
        findings = []

        try:
            # SQL injection assessment
            sql_findings = self._assess_sql_injection(analysis_results)
            findings.extend(sql_findings)

            # Command injection assessment
            command_findings = self._assess_command_injection(analysis_results)
            findings.extend(command_findings)

            # LDAP injection assessment
            ldap_findings = self._assess_ldap_injection(analysis_results)
            findings.extend(ldap_findings)

            # NoSQL injection assessment
            nosql_findings = self._assess_nosql_injection(analysis_results)
            findings.extend(nosql_findings)

            # API injection risks
            api_findings = self._assess_api_injection_risks(analysis_results)
            findings.extend(api_findings)

        except Exception as e:
            self.logger.error(f"Injection assessment failed: {str(e)}")
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title="Assessment Error",
                    description="An error occurred during injection vulnerability assessment",
                    evidence=[str(e)],
                    recommendations=["Review application for injection vulnerabilities manually"],
                )
            )

        return findings

    def _assess_sql_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for SQL injection vulnerabilities."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        if hasattr(string_results, "to_dict"):
            string_data = string_results.to_dict()
        else:
            string_data = string_results

        all_strings = string_data.get("all_strings", [])
        sql_risks = []

        # Look for SQL injection patterns
        for string in all_strings:
            if isinstance(string, str):
                # Check for dynamic SQL construction with user input
                if any(sql_pattern in string.upper() for sql_pattern in self.sql_patterns):
                    if any(user_input in string.lower() for user_input in ["user", "input", "+", "concat", "format"]):
                        sql_risks.append(f"Potential SQL injection: {string[:80]}...")

                # Check for specific dangerous patterns
                dangerous_patterns = [
                    r"SELECT.*\+.*",  # String concatenation in SQL
                    r"WHERE.*\+.*",  # WHERE clause concatenation
                    r"INSERT.*\+.*",  # INSERT concatenation
                    r"UPDATE.*\+.*",  # UPDATE concatenation
                ]

                import re

                for pattern in dangerous_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        sql_risks.append(f"Dangerous SQL pattern: {string[:80]}...")
                        break

        if sql_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.HIGH,
                    title="SQL Injection Risk",
                    description="Application may be vulnerable to SQL injection attacks through dynamic query construction.",
                    evidence=sql_risks[:10],
                    recommendations=[
                        "Use parameterized queries or prepared statements",
                        "Validate and sanitize all user input before database operations",
                        "Use ORM frameworks with built-in injection protection",
                        "Implement strict input validation and type checking",
                        "Apply principle of least privilege for database access",
                        "Use stored procedures with proper parameter handling",
                    ],
                )
            )

        return findings

    def _assess_command_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for command injection vulnerabilities."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        command_risks = []

        for string in all_strings:
            if isinstance(string, str):
                # Check for command execution with user input
                if any(cmd_pattern in string.lower() for cmd_pattern in self.command_patterns):
                    if any(user_input in string.lower() for user_input in ["user", "input", "param", "arg", "+"]):
                        command_risks.append(f"Potential command injection: {string[:80]}...")

                # Check for dangerous shell operators
                dangerous_operators = ["|", "&", ";", "`", "$", "(", ")", "{", "}", "<", ">"]
                if any(op in string for op in dangerous_operators):
                    if any(exec_term in string.lower() for exec_term in ["runtime", "exec", "system"]):
                        command_risks.append(f"Shell injection risk: {string[:80]}...")

        if command_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.HIGH,
                    title="Command Injection Risk",
                    description="Application may be vulnerable to command injection attacks through system command execution.",
                    evidence=command_risks[:8],
                    recommendations=[
                        "Avoid executing system commands with user input",
                        "Use safe APIs instead of shell command execution",
                        "Validate and sanitize all input used in system commands",
                        "Use allowlists for permitted commands and parameters",
                        "Run with minimal privileges and sandboxing",
                        "Consider safer alternatives to Runtime.exec() or system calls",
                    ],
                )
            )

        return findings

    def _assess_ldap_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for LDAP injection vulnerabilities."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        ldap_risks = []

        for string in all_strings:
            if isinstance(string, str):
                # Check for LDAP operations with user input
                if any(ldap_pattern in string for ldap_pattern in self.ldap_patterns):
                    if any(user_input in string.lower() for user_input in ["user", "input", "+", "concat"]):
                        ldap_risks.append(f"Potential LDAP injection: {string[:80]}...")

                # Check for LDAP filter construction
                if (
                    "(" in string
                    and "=" in string
                    and any(ldap_term in string.lower() for ldap_term in ["ldap", "directory", "search"])
                ):
                    if any(user_input in string.lower() for user_input in ["user", "input", "param"]):
                        ldap_risks.append(f"LDAP filter injection risk: {string[:80]}...")

        if ldap_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="LDAP Injection Risk",
                    description="Application may be vulnerable to LDAP injection through dynamic filter construction.",
                    evidence=ldap_risks[:5],
                    recommendations=[
                        "Use parameterized LDAP queries and filters",
                        "Validate and escape LDAP filter characters",
                        "Use LDAP libraries with built-in injection protection",
                        "Implement strict input validation for LDAP operations",
                        "Use allowlists for permitted LDAP operations",
                    ],
                )
            )

        return findings

    def _assess_nosql_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for NoSQL injection vulnerabilities."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        nosql_risks = []

        for string in all_strings:
            if isinstance(string, str):
                # Check for NoSQL operators with user input
                if any(nosql_pattern in string for nosql_pattern in self.nosql_patterns):
                    if any(user_input in string.lower() for user_input in ["user", "input", "param", "json"]):
                        nosql_risks.append(f"Potential NoSQL injection: {string[:80]}...")

                # Check for MongoDB-specific patterns
                mongo_patterns = ["db.", "collection.", "find(", "update(", "insert(", "remove("]
                if any(pattern in string for pattern in mongo_patterns):
                    if "+" in string or "concat" in string.lower():
                        nosql_risks.append(f"MongoDB injection risk: {string[:80]}...")

        if nosql_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="NoSQL Injection Risk",
                    description="Application may be vulnerable to NoSQL injection through dynamic query construction.",
                    evidence=nosql_risks[:6],
                    recommendations=[
                        "Use parameterized NoSQL queries and operations",
                        "Validate and sanitize input used in NoSQL operations",
                        "Use NoSQL libraries with built-in injection protection",
                        "Implement type validation for NoSQL query parameters",
                        "Avoid dynamic query construction with user input",
                        "Use schema validation for NoSQL operations",
                    ],
                )
            )

        return findings

    def _assess_api_injection_risks(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for injection risks in API calls and data processing."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        urls = string_data.get("urls", [])

        api_risks = []

        # Check URLs for injection risks
        for url in urls:
            if isinstance(url, str):
                # Look for dynamic URL construction with user input
                if any(dynamic_indicator in url for dynamic_indicator in ["%s", "{", "}", "+", "concat"]):
                    api_risks.append(f"Dynamic URL construction: {url}")

                # Check for parameter injection risks
                if "?" in url and ("user" in url.lower() or "input" in url.lower()):
                    api_risks.append(f"Parameter injection risk: {url}")

        # Check for XML/JSON injection patterns
        injection_patterns = [
            r"<\?xml.*user.*>",  # XML with user data
            r"json.*user.*input",  # JSON with user input
            r"xml.*concat.*user",  # XML concatenation
            r"parse.*user.*input",  # Parsing user input
        ]

        import re

        for string in all_strings:
            if isinstance(string, str):
                for pattern in injection_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        api_risks.append(f"Data injection risk: {string[:70]}...")
                        break

        if api_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="API and Data Injection Risks",
                    description="Application may be vulnerable to injection through API calls and data processing.",
                    evidence=api_risks[:8],
                    recommendations=[
                        "Use parameterized API calls and avoid URL concatenation",
                        "Validate and sanitize all data used in API requests",
                        "Use safe parsing libraries for XML/JSON processing",
                        "Implement proper input validation for all API parameters",
                        "Use content type validation for API requests",
                        "Apply output encoding for dynamic content generation",
                    ],
                )
            )

        return findings
