#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Dexray Insight Contributors
#
# This file is part of Dexray Insight - Android APK Security Analysis Tool
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Privacy / Personal-Data-Exposure assessment (Phase B1).

Implements a PRIVACY:2024 assessment on top of the :mod:`security.evidence`
PII taxonomy. Four single-responsibility probes are aggregated by
:meth:`PIIAssessment.assess`:

* ``_assess_pii_literals`` — validated PII literals in the string pool
  (review-grade: a literal alone is a *presence* signal, not a leak).
* ``_assess_pii_at_rest`` — sensitive SQLite columns / SharedPreferences keys and
  whether an at-rest encryption posture protects them (Art. 9 columns and
  unencrypted private keys are the headline confirmed facts).
* ``_assess_permission_sink_correlation`` — a granted dangerous permission AND a
  matching data-getter sink (the conjunction is the confirmed collection fact).
* ``_assess_idor_review_queue`` — gRPC/REST identifier-lookup endpoints whose
  *exploitability* needs dynamic verification (review queue, never headline).

The verification-status discipline (see ``VerificationStatus``): only statically
decidable facts are CONFIRMED (Art. 9 storage, unencrypted private key,
permission+sink conjunction, permission typo); IDOR endpoints are NEEDS_DYNAMIC;
bare literals are NEEDS_REVIEW.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from ..core.base_classes import register_assessment
from .evidence import FRAMEWORK_PREFIXES
from .evidence import matches_algorithm_token
from .evidence.descriptors import is_probably_code_identifier
from .evidence.pii_taxonomy import ART9_TOKENS
from .evidence.pii_taxonomy import ENCRYPTION_AT_REST_TOKENS
from .evidence.pii_taxonomy import PERMISSION_SINK_MAP
from .evidence.pii_taxonomy import PII_TAXONOMY
from .evidence.pii_taxonomy import PRIVATE_KEY_PREF_TOKENS
from .evidence.pii_taxonomy import SENSITIVE_COLUMN_TOKENS
from .evidence.pii_taxonomy import SENSITIVE_PREF_KEY_TOKENS
from .evidence.pii_taxonomy import PIICategory
from .evidence.pii_taxonomy import PIIValidator
from .evidence.pii_taxonomy import is_placeholder_or_library_email

_SEVERITY_MAP = {
    "LOW": AnalysisSeverity.LOW,
    "MEDIUM": AnalysisSeverity.MEDIUM,
    "HIGH": AnalysisSeverity.HIGH,
    "CRITICAL": AnalysisSeverity.CRITICAL,
}
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Android-platform permission suffixes for the typo probe. AD_ID is intentionally
# excluded — its canonical form (com.google.android.gms.permission.AD_ID) is NOT
# android.permission.* by design, so it must never be flagged as a typo.
_ANDROID_PERM_SUFFIXES: tuple[str, ...] = (
    "READ_PHONE_NUMBERS",
    "READ_PHONE_STATE",
    "READ_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
)

# IDOR / BOLA endpoint shapes. A match is a real string in the corpus (high
# presence confidence) but its exploitability is not statically decidable.
_IDOR_PATTERNS: tuple[re.Pattern, ...] = (
    # gRPC method: <Service>/<Verb>...By<Selector>, incl. fully-qualified prefixes.
    re.compile(r"\b\w+/(?:Get|List|Find|Lookup)\w*By(?:Username|Alias|Phone|Email)\b"),
    # Retrofit path templates addressing a user by a path variable.
    re.compile(r"profile/users/\{[^}]+\}"),
    re.compile(r"/users/\{[^}]+\}"),
    # PII carried in a query parameter.
    re.compile(r"[?&](?:email|phone|username|user_id|ssn)=", re.IGNORECASE),
)


@register_assessment("pii")
class PIIAssessment(BaseSecurityAssessment):
    """PRIVACY:2024 - Personal Data Exposure assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize the privacy / PII assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "PRIVACY:2024-Personal Data Exposure"
        self.validator = PIIValidator()

    def assess(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None = None
    ) -> list[SecurityFinding]:
        """Run all PII probes and aggregate their findings."""
        findings: list[SecurityFinding] = []
        try:
            findings.extend(self._assess_pii_literals(analysis_results, context))
            findings.extend(self._assess_pii_at_rest(analysis_results, context))
            findings.extend(self._assess_permission_sink_correlation(analysis_results, context))
            findings.extend(self._assess_idor_review_queue(analysis_results, context))
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error(f"PII assessment failed: {exc}")
        return findings

    # ------------------------------------------------------------- literals
    def _assess_pii_literals(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[SecurityFinding]:
        """Validate PII literals across the whole string pool (review-grade seeds)."""
        string_data = self._section(analysis_results, "string_analysis")
        all_strings = string_data.get("all_strings", []) or []
        library_results = self._section(analysis_results, "library_detection")

        # category -> {severity, gdpr_article, evidence, count, confidence}
        buckets: dict[PIICategory, dict[str, Any]] = {}
        for candidate in all_strings:
            if not isinstance(candidate, str):
                continue
            for pattern in PII_TAXONOMY:
                for match in pattern.regex.finditer(candidate):
                    value = match.group(0)
                    if pattern.name == "email":
                        if is_placeholder_or_library_email(value, library_results):
                            continue
                        severity, confidence = pattern.severity, 0.6
                    else:
                        verdict = self.validator.evaluate(value, candidate, pattern)
                        if verdict.rejected:
                            continue
                        severity = verdict.severity or pattern.severity
                        confidence = verdict.confidence
                    self._accumulate_literal(buckets, pattern.category, severity, confidence, value)

        return [self._literal_finding(category, bucket) for category, bucket in buckets.items()]

    def _accumulate_literal(
        self,
        buckets: dict[PIICategory, dict[str, Any]],
        category: PIICategory,
        severity: str,
        confidence: float,
        value: str,
    ) -> None:
        bucket = buckets.setdefault(
            category, {"severity": "LOW", "evidence": [], "count": 0, "confidence": 0.0}
        )
        bucket["count"] += 1
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[bucket["severity"]]:
            bucket["severity"] = severity
        bucket["confidence"] = max(bucket["confidence"], confidence)
        redacted = self._redact(value)
        if redacted not in bucket["evidence"] and len(bucket["evidence"]) < 10:
            bucket["evidence"].append(redacted)

    def _literal_finding(self, category: PIICategory, bucket: dict[str, Any]) -> SecurityFinding:
        # A bare literal is only a presence signal — clamp confidence to review range.
        confidence = min(0.75, max(0.55, bucket["confidence"]))
        return SecurityFinding(
            category=self.owasp_category,
            severity=_SEVERITY_MAP[bucket["severity"]],
            title=f"Personal data literal present: {category.value}",
            description=(
                f"{bucket['count']} validated {category.value} literal(s) were found in the app's "
                "string pool. Presence alone is not a leak; manual review is required to determine "
                "whether the data is collected, stored, or transmitted insecurely."
            ),
            evidence=bucket["evidence"],
            recommendations=[
                "Confirm whether these literals are real user data or test fixtures",
                "Ensure any collected personal data has a lawful basis and is minimized",
                "Verify the data is encrypted in transit and at rest",
            ],
            confidence=confidence,
            verification_status=VerificationStatus.NEEDS_REVIEW,
            additional_data={"pii_category": category.value, "match_count": bucket["count"]},
        )

    # -------------------------------------------------------------- at rest
    def _assess_pii_at_rest(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[SecurityFinding]:
        """Assess sensitive storage schemas / pref keys and their encryption posture."""
        corpus = self._storage_corpus(analysis_results, context)
        encryption_posture = self._has_encryption_posture(corpus)

        art9_evidence: list[str] = []
        sensitive_evidence: list[str] = []
        privkey_evidence: list[str] = []

        for text in corpus:
            if "CREATE TABLE " in text:
                self._scan_create_table(text, art9_evidence, sensitive_evidence)
            elif self._is_pref_key_literal(text):
                self._scan_pref_key(text, privkey_evidence, sensitive_evidence)

        findings: list[SecurityFinding] = []
        if art9_evidence:
            findings.append(self._art9_finding(art9_evidence))
        if privkey_evidence:
            findings.append(self._private_key_finding(privkey_evidence, encryption_posture))
        if sensitive_evidence:
            findings.append(self._sensitive_storage_finding(sensitive_evidence, encryption_posture))
        return findings

    def _scan_create_table(self, ddl: str, art9_evidence: list[str], sensitive_evidence: list[str]) -> None:
        """Route a CREATE TABLE statement's columns into the Art.9 / sensitive buckets."""
        art9_hits = [tok for tok in ART9_TOKENS if matches_algorithm_token(ddl, tok)]
        if art9_hits:
            art9_evidence.append(f"Art.9 columns {sorted(art9_hits)} in: {ddl[:120]}")
            return
        column_hits = [tok for tok in SENSITIVE_COLUMN_TOKENS if matches_algorithm_token(ddl, tok)]
        if not column_hits:
            return
        # Down-rank library-owned DDL (e.g. ExoPlayer cache tables) — keep it as a
        # low-weight review seed rather than a first-party storage concern.
        prefix = "[library] " if self._is_library_ddl(ddl) else ""
        sensitive_evidence.append(f"{prefix}columns {sorted(column_hits)} in: {ddl[:120]}")

    def _scan_pref_key(self, key: str, privkey_evidence: list[str], sensitive_evidence: list[str]) -> None:
        """Route a SharedPreferences key literal into the private-key / sensitive bucket."""
        if any(matches_algorithm_token(key, tok) for tok in PRIVATE_KEY_PREF_TOKENS):
            privkey_evidence.append(key[:120])
            return
        hits = [tok for tok in SENSITIVE_PREF_KEY_TOKENS if matches_algorithm_token(key, tok)]
        if hits:
            sensitive_evidence.append(f"pref key {key[:80]} matches {sorted(hits)}")

    def _art9_finding(self, evidence: list[str]) -> SecurityFinding:
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.HIGH,
            title="GDPR Art.9 special-category data stored at rest",
            description=(
                "A database schema stores GDPR Article 9 special-category personal data "
                "(e.g. health, religion, ethnicity, sexual orientation). Such data carries the "
                "strictest processing and protection obligations."
            ),
            evidence=evidence[:10],
            recommendations=[
                "Confirm a lawful basis under GDPR Art.9 for processing this data",
                "Encrypt the database at rest (e.g. SQLCipher / EncryptedSharedPreferences)",
                "Apply strict access controls and data minimization",
            ],
            confidence=0.8,
            verification_status=VerificationStatus.CONFIRMED,
            additional_data={"gdpr_article": "Art.9"},
        )

    def _private_key_finding(self, evidence: list[str], encryption_posture: bool) -> SecurityFinding:
        if encryption_posture:
            return SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.LOW,
                title="Private-key material stored with encryption posture",
                description=(
                    "A private-key SharedPreferences key was found, but an at-rest encryption "
                    "posture (EncryptedSharedPreferences / SQLCipher / MasterKey) is present."
                ),
                evidence=evidence[:10],
                recommendations=["Verify the private key is actually stored via the encrypted store"],
                confidence=0.6,
                verification_status=VerificationStatus.NEEDS_REVIEW,
                additional_data={"pii_category": PIICategory.CREDENTIAL.value},
            )
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.CRITICAL,
            title="Private key stored in plaintext SharedPreferences",
            description=(
                "A private-key SharedPreferences key was found with no at-rest encryption posture. "
                "Private keys in plaintext preferences are readable on rooted or backed-up devices."
            ),
            evidence=evidence[:10],
            recommendations=[
                "Store private keys in the Android Keystore, never in SharedPreferences",
                "If preferences must be used, migrate to EncryptedSharedPreferences with a MasterKey",
            ],
            confidence=0.85,
            verification_status=VerificationStatus.CONFIRMED,
            additional_data={"pii_category": PIICategory.CREDENTIAL.value},
        )

    def _sensitive_storage_finding(self, evidence: list[str], encryption_posture: bool) -> SecurityFinding:
        if encryption_posture:
            return SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.LOW,
                title="Sensitive data stored with encryption posture",
                description=(
                    "Sensitive columns / preference keys were found alongside an at-rest encryption "
                    "posture. This is informational: verify the sensitive data uses the encrypted store."
                ),
                evidence=evidence[:10],
                recommendations=["Confirm sensitive fields are written through the encrypted store"],
                confidence=0.6,
                verification_status=VerificationStatus.NEEDS_REVIEW,
                additional_data={"encryption_posture": True},
            )
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.MEDIUM,
            title="Sensitive data stored without encryption posture",
            description=(
                "Sensitive columns / preference keys were found with no evidence of an at-rest "
                "encryption posture. Unencrypted local storage of personal data is common but "
                "should be reviewed for exposure on rooted or backed-up devices."
            ),
            evidence=evidence[:10],
            recommendations=[
                "Adopt EncryptedSharedPreferences / SQLCipher for personal data",
                "Disable Android auto-backup for sensitive datastores",
            ],
            confidence=0.6,
            verification_status=VerificationStatus.NEEDS_REVIEW,
            additional_data={"encryption_posture": False},
        )

    # ------------------------------------------------ permission + sink map
    def _assess_permission_sink_correlation(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[SecurityFinding]:
        """Correlate granted dangerous permissions with matching data-getter sinks."""
        perm_data = self._section(analysis_results, "permission_analysis")
        permissions = perm_data.get("all_permissions") or perm_data.get("permissions") or []
        permissions = [p for p in permissions if isinstance(p, str)]

        findings: list[SecurityFinding] = []
        findings.extend(self._permission_typo_findings(permissions))

        api_data = self._section(analysis_results, "api_invocation")
        api_calls = api_data.get("api_calls", []) or []
        if not api_calls:
            # api_invocation is off by default — self-suppress correlation findings.
            return findings

        call_texts = [self._api_call_text(call) for call in api_calls]
        for permission, sinks in PERMISSION_SINK_MAP.items():
            if not any(matches_algorithm_token(p, permission) for p in permissions):
                continue
            matched_sinks = [s for s in sinks if any(s in text for text in call_texts)]
            if matched_sinks:
                findings.append(self._correlation_finding(permission, matched_sinks))
        return findings

    def _permission_typo_findings(self, permissions: list[str]) -> list[SecurityFinding]:
        """Flag android permission suffixes declared without the android.permission. prefix."""
        findings: list[SecurityFinding] = []
        for permission in permissions:
            if "android.permission." in permission:
                continue
            for suffix in _ANDROID_PERM_SUFFIXES:
                if matches_algorithm_token(permission, suffix):
                    findings.append(
                        SecurityFinding(
                            category=self.owasp_category,
                            severity=AnalysisSeverity.LOW,
                            title="Malformed Android permission (missing android.permission. prefix)",
                            description=(
                                f"Permission '{permission}' carries a known Android permission suffix "
                                f"('{suffix}') but is not namespaced under android.permission., so it is "
                                "silently ignored at runtime."
                            ),
                            evidence=[permission],
                            recommendations=[f"Use the canonical name android.permission.{suffix}"],
                            confidence=0.9,
                            verification_status=VerificationStatus.CONFIRMED,
                            additional_data={"permission": permission, "expected_suffix": suffix},
                        )
                    )
                    break
        return findings

    def _correlation_finding(self, permission: str, matched_sinks: list[str]) -> SecurityFinding:
        # AD_ID + advertising-id lookup is near-universal — down-rank to LOW.
        down_ranked = permission == "AD_ID"
        severity = AnalysisSeverity.LOW if down_ranked else AnalysisSeverity.MEDIUM
        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            title=f"Personal data collection: {permission} permission + matching sink",
            description=(
                f"The app both requests the {permission} permission and calls a matching data-getter "
                f"sink ({', '.join(matched_sinks)}). The conjunction confirms the data is collected."
            ),
            evidence=[f"permission={permission}", f"sinks={matched_sinks}"],
            recommendations=[
                "Confirm the collected identifier/location is necessary and disclosed",
                "Minimize retention and avoid transmitting the identifier off-device",
            ],
            confidence=0.7,
            verification_status=VerificationStatus.CONFIRMED,
            additional_data={"permission": permission, "sinks": matched_sinks, "down_ranked": down_ranked},
        )

    # --------------------------------------------------------- idor review
    def _assess_idor_review_queue(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[SecurityFinding]:
        """Queue identifier-lookup endpoints for dynamic (server-side authz) review."""
        string_data = self._section(analysis_results, "string_analysis")
        corpus: list[str] = []
        corpus.extend(x for x in (string_data.get("urls") or []) if isinstance(x, str))
        corpus.extend(x for x in (string_data.get("all_strings") or []) if isinstance(x, str))
        if context is not None:
            try:
                corpus.extend(x for x in context.get_dex_strings() if isinstance(x, str))
            except Exception:
                pass

        seen: set[str] = set()
        matches: list[str] = []
        for text in corpus:
            for pattern in _IDOR_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group(0)
                    if value not in seen:
                        seen.add(value)
                        matches.append(value)

        return [self._idor_finding(value) for value in matches]

    def _idor_finding(self, value: str) -> SecurityFinding:
        return SecurityFinding(
            category="A01:2021-Broken Access Control",
            severity=AnalysisSeverity.MEDIUM,
            title="Potential IDOR/BOLA - manual review (unconfirmed)",
            description=(
                "An endpoint that looks up an object by a user-controlled identifier was found. "
                "Whether it is exploitable depends on server-side authorization, which cannot be "
                "determined statically — this is queued for dynamic review."
            ),
            evidence=[value[:160]],
            recommendations=[
                "Dynamically verify the server enforces per-object authorization (BOLA/IDOR)",
                "Confirm identifiers are not directly enumerable without access checks",
            ],
            confidence=0.9,
            verification_status=VerificationStatus.NEEDS_DYNAMIC,
            additional_data={"review_queue": True, "confirmed": False, "verification": "dynamic"},
        )

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _section(analysis_results: dict[str, Any], key: str) -> dict[str, Any]:
        """Return a module's result as a dict, tolerating result objects."""
        section = analysis_results.get(key, {})
        if hasattr(section, "to_dict"):
            section = section.to_dict()
        return section if isinstance(section, dict) else {}

    def _storage_corpus(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[str]:
        """Combine string-pool literals with the shared DEX string extraction."""
        string_data = self._section(analysis_results, "string_analysis")
        corpus: list[str] = [x for x in (string_data.get("all_strings") or []) if isinstance(x, str)]
        if context is not None:
            try:
                corpus.extend(x for x in context.get_dex_strings() if isinstance(x, str))
            except Exception:
                pass
        return corpus

    @staticmethod
    def _has_encryption_posture(corpus: list[str]) -> bool:
        lowered_tokens = [tok.lower() for tok in ENCRYPTION_AT_REST_TOKENS]
        for text in corpus:
            lowered = text.lower()
            if any(tok in lowered for tok in lowered_tokens):
                return True
        return False

    @staticmethod
    def _is_library_ddl(ddl: str) -> bool:
        lowered = ddl.lower()
        if "exoplayer" in lowered:
            return True
        return any(prefix.lower() in lowered for prefix in FRAMEWORK_PREFIXES)

    @staticmethod
    def _is_pref_key_literal(text: str) -> bool:
        """A pref key is a short identifier-shaped literal (no whitespace/operators)."""
        if not text or len(text) > 128:
            return False
        return is_probably_code_identifier(text)

    @staticmethod
    def _api_call_text(call: Any) -> str:
        """Lowercased text of an api_invocation call (string or dict shape)."""
        if isinstance(call, str):
            return call.lower()
        if isinstance(call, dict):
            return " ".join(str(v) for v in call.values()).lower()
        return str(call).lower()

    @staticmethod
    def _redact(value: str) -> str:
        """Mask the middle of a matched literal so raw PII never enters the report."""
        token = value.strip()
        if len(token) <= 4:
            return "*" * len(token)
        return f"{token[:2]}{'*' * (len(token) - 4)}{token[-2:]}"
