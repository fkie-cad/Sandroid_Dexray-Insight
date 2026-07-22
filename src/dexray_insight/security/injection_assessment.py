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
from .evidence import is_probably_code_identifier
from .evidence import list_sink_calls
from .evidence import list_weak_command_signals
from .evidence import looks_like_type_descriptor
from .evidence.whole_word import matches_algorithm_token

# SQL verbs / clauses used to recognise a *real* dynamic-query shape (as opposed
# to a bare SQL keyword co-occurring with a "+" somewhere in a class descriptor).
_SQL_VERBS = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "MERGE", "TRUNCATE", "UNION")
_SQL_CLAUSES = ("FROM", "WHERE", "INTO", "VALUES", "SET", "TABLE", "JOIN")
_SQL_CONCAT_HINTS = ("+", "||", "concat", "%s", "format", "{")

# Shell metacharacters that indicate command chaining / interpolation.
_SHELL_METACHARS = ("|", ";", "`", "&&", "$(", "$'", ">", "<")
_SHELL_TOKENS = ("sh", "bash", "cmd", "exec", "system")


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

        # Evidence gating: require a real API sink before promoting a string-only
        # heuristic hit to MEDIUM/HIGH. When True (default) a string-only hit is
        # DEMOTED to a LOW "unproven (review)" finding rather than dropped.
        self.require_sink = bool(config.get("require_sink", True))

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _get_all_strings(analysis_results: dict[str, Any]) -> list:
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        if not isinstance(string_data, dict):
            return []
        strings = string_data.get("all_strings", [])
        return strings if isinstance(strings, list) else []

    @staticmethod
    def _looks_like_sql_query(string: str) -> bool:
        """A real dynamic SQL query: verb + clause + concatenation, not a descriptor."""
        if not isinstance(string, str) or " " not in string:
            return False
        if looks_like_type_descriptor(string):
            return False
        has_verb = any(matches_algorithm_token(string, verb) for verb in _SQL_VERBS)
        has_clause = any(matches_algorithm_token(string, clause) for clause in _SQL_CLAUSES)
        lower = string.lower()
        has_concat = any(hint in string if hint in ("+", "||", "%s", "{") else hint in lower for hint in _SQL_CONCAT_HINTS)
        return has_verb and has_clause and has_concat

    @staticmethod
    def _looks_like_shell_command(string: str) -> bool:
        """A real shell command: shell token + metachar + whitespace, not a descriptor/identifier."""
        if not isinstance(string, str) or " " not in string:
            return False
        if looks_like_type_descriptor(string) or is_probably_code_identifier(string):
            return False
        has_token = any(matches_algorithm_token(string, token) for token in _SHELL_TOKENS)
        has_meta = any(meta in string for meta in _SHELL_METACHARS)
        return has_token and has_meta

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

    _SQL_RECOMMENDATIONS = [
        "Use parameterized queries or prepared statements",
        "Validate and sanitize all user input before database operations",
        "Use ORM frameworks with built-in injection protection",
        "Implement strict input validation and type checking",
        "Apply principle of least privilege for database access",
        "Use stored procedures with proper parameter handling",
    ]

    _COMMAND_RECOMMENDATIONS = [
        "Avoid executing system commands with user input",
        "Use safe APIs instead of shell command execution",
        "Validate and sanitize all input used in system commands",
        "Use allowlists for permitted commands and parameters",
        "Run with minimal privileges and sandboxing",
        "Consider safer alternatives to Runtime.exec() or system calls",
    ]

    def _assess_sql_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for SQL injection vulnerabilities.

        Primary evidence is a real SQLite API sink (rawQuery/execSQL/QueryBuilder).
        Dynamic-query strings only corroborate; a string-only hit with no sink is
        demoted to LOW "unproven (review)" (kept, not dropped) when require_sink.
        """
        sink_calls = list_sink_calls(analysis_results, "sql")
        sink_evidence = [
            f"SQL sink: {c.get('called_class', '')}.{c.get('called_method', '')}" for c in sink_calls
        ]

        string_risks = [
            f"Dynamic SQL query: {s[:80]}"
            for s in self._get_all_strings(analysis_results)
            if self._looks_like_sql_query(s)
        ]

        return self._build_injection_finding(
            title="SQL Injection",
            description="Application may be vulnerable to SQL injection through dynamic query construction.",
            sink_evidence=sink_evidence,
            string_risks=string_risks,
            recommendations=self._SQL_RECOMMENDATIONS,
        )

    def _assess_command_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for command injection vulnerabilities.

        Primary evidence is a Runtime.exec / ProcessBuilder sink. Reflection and
        dynamic class-loading are treated as weaker corroborating signals so that
        obfuscated malware hiding a real exec is not silently cleared.
        """
        sink_calls = list_sink_calls(analysis_results, "command")
        sink_evidence = [
            f"Command sink: {c.get('called_class', '')}.{c.get('called_method', '')}" for c in sink_calls
        ]

        weak_signals = list_weak_command_signals(analysis_results)

        string_risks = [
            f"Shell command construction: {s[:80]}"
            for s in self._get_all_strings(analysis_results)
            if self._looks_like_shell_command(s)
        ]
        # Weak reflective/dynamic-loading signals corroborate command injection
        # even without a hard sink (false-negative guard for obfuscated apps).
        string_risks.extend(weak_signals)

        return self._build_injection_finding(
            title="Command Injection",
            description="Application may be vulnerable to command injection through system command execution.",
            sink_evidence=sink_evidence,
            string_risks=string_risks,
            recommendations=self._COMMAND_RECOMMENDATIONS,
        )

    def _build_injection_finding(
        self,
        title: str,
        description: str,
        sink_evidence: list[str],
        string_risks: list[str],
        recommendations: list[str],
    ) -> list[SecurityFinding]:
        """Assemble an injection finding with evidence-weighted severity/confidence."""
        if sink_evidence:
            # Sink present: HIGH if also corroborated by a query/command string,
            # else MEDIUM. Confidence is high because a real API sink exists.
            severity = AnalysisSeverity.HIGH if string_risks else AnalysisSeverity.MEDIUM
            confidence = 0.85 if string_risks else 0.7
            return [
                SecurityFinding(
                    category=self.owasp_category,
                    severity=severity,
                    title=f"{title} Risk",
                    description=description,
                    evidence=(sink_evidence + string_risks)[:10],
                    recommendations=recommendations,
                    confidence=confidence,
                )
            ]

        if not string_risks:
            return []

        # No sink, only string heuristics.
        if self.require_sink:
            return [
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title=f"{title} Risk (unproven, review)",
                    description=(
                        f"{description} No supporting API sink was found; this is a string-only "
                        "heuristic hit that requires manual review."
                    ),
                    evidence=string_risks[:10],
                    recommendations=recommendations,
                    confidence=0.35,
                )
            ]

        return [
            SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title=f"{title} Risk",
                description=description,
                evidence=string_risks[:10],
                recommendations=recommendations,
                confidence=0.4,
            )
        ]

    def _assess_ldap_injection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for LDAP injection vulnerabilities."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        ldap_risks = []

        for string in all_strings:
            if not isinstance(string, str) or looks_like_type_descriptor(string):
                continue
            # Require an actual LDAP URI scheme plus a dynamic-construction hint;
            # a bare "search"/"directory" substring is not evidence.
            has_ldap_uri = "ldap://" in string.lower() or "ldaps://" in string.lower()
            has_dynamic = any(hint in string.lower() for hint in ["user", "input", "+", "concat"])
            if has_ldap_uri and has_dynamic:
                ldap_risks.append(f"Potential LDAP injection: {string[:80]}")

        if ldap_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    # Demoted to LOW: no LDAP sink catalog exists, so even a URI +
                    # dynamic hint is unproven without data-flow.
                    severity=AnalysisSeverity.LOW,
                    title="LDAP Injection Risk (unproven, review)",
                    description="Application may be vulnerable to LDAP injection through dynamic filter construction.",
                    evidence=ldap_risks[:5],
                    confidence=0.3,
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
            if not isinstance(string, str) or looks_like_type_descriptor(string):
                continue
            # Require a NoSQL operator token AND a dynamic-construction hint; drop
            # bare-substring co-occurrence.
            has_operator = any(nosql_pattern in string for nosql_pattern in self.nosql_patterns)
            has_dynamic = ("+" in string) or ("concat" in string.lower())
            if has_operator and has_dynamic and any(
                hint in string.lower() for hint in ["user", "input", "param", "json"]
            ):
                nosql_risks.append(f"Potential NoSQL injection: {string[:80]}")

        if nosql_risks:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    # Demoted to LOW: no NoSQL sink catalog, unproven without data-flow.
                    severity=AnalysisSeverity.LOW,
                    title="NoSQL Injection Risk (unproven, review)",
                    description="Application may be vulnerable to NoSQL injection through dynamic query construction.",
                    evidence=nosql_risks[:6],
                    confidence=0.3,
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
