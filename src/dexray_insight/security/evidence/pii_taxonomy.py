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

"""PII taxonomy + validation for the Privacy assessment (Phase B1).

This module is the data + precision layer for ``pii_assessment``. It mirrors the
split used by :mod:`security.secret_validation`:

* a catalog of *shape* detectors (:data:`PII_TAXONOMY`) that only say "this string
  LOOKS like a credit card / phone / SSN / coordinate", and
* a :class:`PIIValidator` whose :meth:`~PIIValidator.evaluate` turns a raw regex
  match into a :class:`PIIVerdict` (rejected / severity / confidence / basis),
  killing the false positives that a bare regex produces (a 9-digit Zendesk
  article id, a non-Luhn 16-digit run, a bare 10-digit id that is not a phone).

The GDPR framing: Art. 9 "special category" data (health, religion, ethnicity,
sexual orientation, political opinion, biometrics) is always treated as HIGH and
tagged with its article, because its unlawful processing carries the heaviest
regulatory risk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .descriptors import is_probably_placeholder


class PIICategory(str, Enum):
    """Taxonomy of personal-data categories the Privacy assessment reasons about."""

    IDENTIFIER = "identifier"
    FINANCIAL = "financial"
    HEALTH_ART9 = "health_art9"
    LOCATION = "location"
    CREDENTIAL = "credential"
    DEVICE_ID = "device_id"
    CONTACT = "contact"


@dataclass
class PIIPattern:
    """A single PII shape detector.

    Attributes:
        name: Stable identifier for the pattern (used in evidence/labels).
        category: Which :class:`PIICategory` a match belongs to.
        regex: Compiled detection regex applied to decompiled strings.
        validator: Key selecting a :class:`PIIValidator` dispatch branch, or
            ``None`` when the pattern is handled by a dedicated path (email is
            resolved via the library/placeholder allowlist, not the validator).
        severity: Base severity string ("LOW"/"MEDIUM"/"HIGH"/"CRITICAL").
        description: Human-readable description of what the pattern captures.
        gdpr_article: GDPR article annotation (e.g. "Art.9"), or ``None``.
    """

    name: str
    category: PIICategory
    regex: re.Pattern
    validator: str | None
    severity: str
    description: str
    gdpr_article: str | None = None


@dataclass
class PIIVerdict:
    """Outcome of validating a single PII match (mirrors ``SecretVerdict``).

    Attributes:
        rejected: When True the match is a false positive and must be discarded.
        category: The resolved :class:`PIICategory` (echoes the pattern's).
        severity: Possibly refined severity string, or None to keep the pattern's.
        confidence: 0.0-1.0 confidence the match is genuine PII.
        label: Human-readable classification label.
        basis: Why the verdict was chosen (e.g. "luhn:valid", "e164:no_context").
        reason: Rejection reason when ``rejected`` is True.
    """

    rejected: bool = False
    category: PIICategory | None = None
    severity: str | None = None
    confidence: float = 0.0
    label: str | None = None
    basis: str | None = None
    reason: str | None = None


# --------------------------------------------------------------------- taxonomy
# Credit card: a run of 13-19 digits, optionally separated by a single space or
# hyphen. Luhn validation (see PIIValidator) removes the vast majority of the
# false positives a bare digit-run regex produces.
_CREDIT_CARD_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# E.164 phone: leading '+', a non-zero country digit, then 7-14 more digits.
_PHONE_E164_RE = re.compile(r"\+[1-9]\d{7,14}")

# US SSN: strictly hyphenated AAA-GG-SSSS with digit boundaries either side.
_SSN_US_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# Decimal lat/long pair. The mandatory decimal point rules out integer id pairs.
_LATLONG_RE = re.compile(r"-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+")

# Email address (RFC-ish, deliberately permissive; allowlist does the filtering).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


PII_TAXONOMY: list[PIIPattern] = [
    PIIPattern(
        name="credit_card",
        category=PIICategory.FINANCIAL,
        regex=_CREDIT_CARD_RE,
        validator="luhn",
        severity="HIGH",
        description="Payment card number (Luhn-valid 13-19 digit PAN)",
    ),
    PIIPattern(
        name="phone_e164",
        category=PIICategory.CONTACT,
        regex=_PHONE_E164_RE,
        validator="e164",
        severity="MEDIUM",
        description="Phone number in E.164 international format",
    ),
    PIIPattern(
        name="ssn_us",
        category=PIICategory.IDENTIFIER,
        regex=_SSN_US_RE,
        validator="ssn",
        severity="HIGH",
        description="US Social Security Number (AAA-GG-SSSS)",
    ),
    PIIPattern(
        name="latlong",
        category=PIICategory.LOCATION,
        regex=_LATLONG_RE,
        validator="geo",
        severity="MEDIUM",
        description="Geographic coordinate pair (latitude, longitude)",
    ),
    PIIPattern(
        name="email",
        category=PIICategory.CONTACT,
        regex=_EMAIL_RE,
        validator=None,
        severity="LOW",
        description="Email address",
    ),
]


# ------------------------------------------------------------- context tokens
# Context tokens that, when present near a bare numeric run, corroborate that the
# number really is a phone / SSN (used to accept otherwise-ambiguous shapes).
_PHONE_CONTEXT_TOKENS = ("phone", "tel", "msisdn", "mobile", "cell")
_SSN_CONTEXT_TOKENS = ("ssn", "social", "tax")


# --------------------------------------------------------------- email allowlist
# Domain fragments owned by SDKs / analytics / crash reporters / documentation.
# An email under any of these is developer/library boilerplate, never user PII.
LIBRARY_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "crashlytics",
        "fabric",
        "firebaseio",
        "firebase",
        "applovin",
        "unity3d",
        "revenuecat",
        "zendesk",
        "example.com",
        "example.org",
        "google.com",
        "android.com",
        "schema.org",
        "w3.org",
        "apache.org",
        "sentry.io",
        "bugsnag.com",
        "onesignal.com",
    }
)


def is_placeholder_or_library_email(email: str, library_results=None) -> bool:
    """Return True if ``email`` is a placeholder or library/SDK boilerplate address.

    Reuses :func:`descriptors.is_probably_placeholder` for template values
    (``your_email@...``, ``test@...``) and matches the domain against
    :data:`LIBRARY_EMAIL_DOMAINS`. ``library_results`` is accepted for API parity
    and future package-corroboration; it is not required for the domain decision.
    """
    if not isinstance(email, str) or not email:
        return True
    local, _, domain = email.partition("@")
    # Placeholder anywhere: the whole address, its local part, or a test/example
    # domain (e.g. ``your_email@test.com`` -> domain ``test.com`` is boilerplate).
    if is_probably_placeholder(email) or is_probably_placeholder(local) or is_probably_placeholder(domain):
        return True
    domain = domain.lower()
    if not domain:
        return True
    return any(fragment in domain for fragment in LIBRARY_EMAIL_DOMAINS)


# ---------------------------------------------------------- storage token sets
# Whole-word matched against SQLite column names and SharedPreferences keys.
SENSITIVE_COLUMN_TOKENS: frozenset[str] = frozenset(
    {
        "body",
        "message",
        "contact",
        "phone",
        "email",
        "address",
        "dob",
        "birth",
        "latitude",
        "longitude",
        "password",
    }
)

# GDPR Art. 9 "special category" tokens. A column/key hit here is always HIGH.
ART9_TOKENS: frozenset[str] = frozenset(
    {
        "religion",
        "ethnicity",
        "orientation",
        "sexual",
        "health",
        "political",
        "biometric",
    }
)

# SharedPreferences key tokens that indicate a stored credential/secret at rest.
SENSITIVE_PREF_KEY_TOKENS: frozenset[str] = frozenset(
    {
        "priv.key",
        "private_key",
        "auth",
        "token",
        "password",
        "secret",
        "session",
    }
)

# Tokens that evidence an at-rest encryption posture (encrypted prefs / DB).
# NOTE: the bare ``MasterKey``/``MasterKeys`` identifiers were intentionally
# removed (R8b-2). Whole-word matching still matched a benign camelCase field or
# variable named ``masterKey`` and falsely asserted encryption-at-rest, silencing
# genuine plaintext-private-key findings. The Jetpack MasterKey API always lives
# in ``androidx.security.crypto`` and real usage co-occurs with
# ``EncryptedSharedPreferences``, so those unambiguous tokens still detect a real
# posture without the false positive.
ENCRYPTION_AT_REST_TOKENS: frozenset[str] = frozenset(
    {
        "EncryptedSharedPreferences",
        "androidx.security.crypto",
        "net.sqlcipher",
        "SupportFactory",
    }
)

# Private-key pref tokens: presence WITHOUT an encryption posture is CRITICAL.
PRIVATE_KEY_PREF_TOKENS: frozenset[str] = frozenset({"priv.key", "private_key"})


# ------------------------------------------------------ permission -> sink map
# Each granted dangerous permission maps to lowercased API sink-method fragments.
# A finding requires BOTH the permission AND a matching sink call (conjunction).
PERMISSION_SINK_MAP: dict[str, tuple[str, ...]] = {
    "READ_PHONE_NUMBERS": ("getline1number", "getphonenumber"),
    "READ_PHONE_STATE": ("getline1number", "getdeviceid", "getsubscriberid", "getimei"),
    "AD_ID": ("getadvertisingidinfo",),
    "ACCESS_FINE_LOCATION": ("getlastknownlocation", "requestlocationupdates", "getlastlocation"),
    "ACCESS_COARSE_LOCATION": ("getlastknownlocation", "getlastlocation"),
    "READ_CONTACTS": ("contactscontract",),
}


class PIIValidator:
    """Turn a raw PII regex match into a :class:`PIIVerdict` (precision layer).

    Mirrors :class:`security.secret_validation.SecretValidator`: a single
    :meth:`evaluate` entry point dispatches on the pattern's ``validator`` key to
    a targeted checker. Rejecting verdicts drop the match; accepting verdicts may
    refine severity/confidence and always carry a ``basis``.
    """

    def evaluate(self, value: str, full_context: str, pattern: PIIPattern) -> PIIVerdict:
        """Validate a single match against the checker named by ``pattern.validator``."""
        dispatch = {
            "luhn": self._evaluate_luhn,
            "e164": self._evaluate_e164,
            "ssn": self._evaluate_ssn,
            "geo": self._evaluate_geo,
        }
        checker = dispatch.get(pattern.validator or "")
        if checker is None:
            # No validator (e.g. email) — accept at the pattern's severity; the
            # caller applies the dedicated allowlist path instead.
            return PIIVerdict(
                rejected=False,
                category=pattern.category,
                severity=pattern.severity,
                confidence=0.6,
                label=pattern.description,
                basis="no_validator",
            )
        return checker(value, full_context, pattern)

    # ------------------------------------------------------------------ luhn
    def _evaluate_luhn(self, value: str, full_context: str, pattern: PIIPattern) -> PIIVerdict:
        """Accept only Luhn-valid 13-19 digit PANs (kills id/timestamp false positives)."""
        digits = re.sub(r"\D", "", value)
        if not 13 <= len(digits) <= 19:
            return PIIVerdict(rejected=True, basis="luhn:length", reason=f"{len(digits)} digits out of range")
        if not self._luhn_ok(digits):
            return PIIVerdict(rejected=True, basis="luhn:checksum", reason="fails Luhn checksum")
        return PIIVerdict(
            rejected=False,
            category=PIICategory.FINANCIAL,
            severity=pattern.severity,
            confidence=0.75,
            label="payment card (Luhn-valid)",
            basis="luhn:valid",
        )

    @staticmethod
    def _luhn_ok(digits: str) -> bool:
        """Standard Luhn (mod-10) checksum verification."""
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            digit = int(char)
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    # ------------------------------------------------------------------ e164
    def _evaluate_e164(self, value: str, full_context: str, pattern: PIIPattern) -> PIIVerdict:
        """Accept '+'-prefixed E.164 numbers; a bare 10-digit run needs phone context."""
        stripped = value.strip()
        has_plus = stripped.startswith("+")
        digits = re.sub(r"\D", "", stripped)
        if not 8 <= len(digits) <= 15:
            return PIIVerdict(rejected=True, basis="e164:length", reason=f"{len(digits)} digits out of range")

        if has_plus:
            return PIIVerdict(
                rejected=False,
                category=PIICategory.CONTACT,
                severity=pattern.severity,
                confidence=0.7,
                label="phone number (E.164)",
                basis="e164:plus",
            )

        # Bare digit run: only a phone/tel/msisdn context token rescues it.
        if self._has_context_token(full_context, _PHONE_CONTEXT_TOKENS):
            return PIIVerdict(
                rejected=False,
                category=PIICategory.CONTACT,
                severity=pattern.severity,
                confidence=0.6,
                label="phone number (context-corroborated)",
                basis="e164:context",
            )
        return PIIVerdict(rejected=True, basis="e164:no_context", reason="bare number without phone context")

    # ------------------------------------------------------------------- ssn
    def _evaluate_ssn(self, value: str, full_context: str, pattern: PIIPattern) -> PIIVerdict:
        """Accept structurally valid US SSNs; context corroboration boosts confidence."""
        match = re.search(r"(\d{3})-(\d{2})-(\d{4})", value)
        if not match:
            return PIIVerdict(rejected=True, basis="ssn:shape", reason="not AAA-GG-SSSS")
        area, group, serial = int(match.group(1)), int(match.group(2)), int(match.group(3))

        structural_ok = (
            area not in (0, 666)
            and not (900 <= area <= 999)
            and group != 0
            and serial != 0
        )
        has_context = self._has_context_token(full_context, _SSN_CONTEXT_TOKENS)

        if not (structural_ok or has_context):
            return PIIVerdict(rejected=True, basis="ssn:structure", reason="fails SSN structural rules")

        confidence = 0.75 if has_context else 0.6
        return PIIVerdict(
            rejected=False,
            category=PIICategory.IDENTIFIER,
            severity=pattern.severity,
            confidence=confidence,
            label="US Social Security Number",
            basis="ssn:context" if has_context else "ssn:structure",
        )

    # ------------------------------------------------------------------- geo
    def _evaluate_geo(self, value: str, full_context: str, pattern: PIIPattern) -> PIIVerdict:
        """Accept in-range decimal lat/long pairs; reject 0.0/0.0 and integer pairs."""
        parts = value.replace(" ", "").split(",")
        if len(parts) != 2:
            return PIIVerdict(rejected=True, basis="geo:shape", reason="not a lat,long pair")
        try:
            lat, lon = float(parts[0]), float(parts[1])
        except ValueError:
            return PIIVerdict(rejected=True, basis="geo:parse", reason="non-numeric coordinate")

        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            return PIIVerdict(rejected=True, basis="geo:range", reason="coordinate out of range")
        if lat == 0.0 and lon == 0.0:
            return PIIVerdict(rejected=True, basis="geo:null_island", reason="0.0/0.0 placeholder")
        if lat.is_integer() and lon.is_integer():
            return PIIVerdict(rejected=True, basis="geo:integer", reason="integer-only pair")

        return PIIVerdict(
            rejected=False,
            category=PIICategory.LOCATION,
            severity=pattern.severity,
            confidence=0.65,
            label="geographic coordinate",
            basis="geo:valid",
        )

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _has_context_token(full_context: str, tokens: tuple[str, ...]) -> bool:
        lowered = (full_context or "").lower()
        return any(token in lowered for token in tokens)
