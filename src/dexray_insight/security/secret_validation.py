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

"""Precision/recall gating for secret detection (PR-5).

``SecretValidator`` sits between the raw regex match and the reported finding. It
implements two opposing goals at once:

* **Precision** — drop or downgrade generic-pattern false positives (base64 image
  blobs, low-entropy strings, non-JWT ``ey...`` class names) that previously
  produced fake CRITICAL/HIGH secrets.
* **Recall** — make sure *structural* keys with a distinctive prefix/format are
  NEVER dropped by entropy/context heuristics (that is what previously hid the 4
  real Kik client keys), and reclassify them by their real risk class using the
  ``data/known_safe_credentials.yaml`` registry.

The split:

* **structural** patterns (distinctive prefix/format: PEM/SSH keys, AWS ids,
  GitHub tokens, ``AIza*``, ``ca-app-pub-``, ``key_live_``, ``sk_live_`` …) skip
  the entropy/context/false-positive gate entirely — only their *targeted*
  validators run (JWT header decode, binary-signature check, allowlist class
  reclassification).
* **generic** patterns (``base64_key_*``, ``hex_key_*``, ``high_entropy_string``,
  ``generic_secret``) get the FULL gate: min-entropy, max-length, required
  context, false-positive heuristics, base64->binary rejection, and the
  configurable confidence floor.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import math
import re
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Generic patterns are prefix-less "shape" detectors. They carry the full FP gate.
# Everything NOT in this set is treated as structural (distinctive prefix/format)
# and is exempt from entropy/context/FP gating so real keys are never dropped.
GENERIC_PATTERN_NAMES: frozenset[str] = frozenset(
    {
        "base64_key_long",
        "base64_key_medium",
        "hex_key_256",
        "hex_key_128",
        "high_entropy_string",
        "generic_secret",
    }
)

# The base64/entropy "leakage" family: prefix-less shape detectors whose hits are
# dominated (on real APKs) by DEX class descriptors and slash URL/package paths
# rather than secrets. A path-like / DEX-descriptor hit in ANY of these must be
# HARD-DROPPED, not soft-downgraded to LOW, or the "Information Leakage" bucket
# balloons to tens of thousands of findings. base64 punctuation ('+'/'=') and a
# lack of identifier-path structure keep genuine high-entropy secrets out of the
# drop (see ``_looks_like_path`` / ``_looks_like_dex_descriptor``).
_PATH_DROP_PATTERN_NAMES: frozenset[str] = frozenset(
    {
        "high_entropy_string",
        "base64_key_long",
        "base64_key_medium",
    }
)

# Base64url alphabet for JWT segment decoding.
_JWT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# A camelCase/PascalCase "word": an optional leading capital followed by >=2
# lowercase letters (so a dictionary-length token, min length 3). Used by
# ``_looks_like_code_identifier`` to segment long Java method/class names.
_CODE_WORD_RE = re.compile(r"[A-Z]?[a-z]{2,}")

# Firebase / Google-services co-location markers. When an AIza key sits next to
# any of these, it is almost certainly a client Firebase key -> LOW.
_FIREBASE_CONTEXT_MARKERS = (
    "firebase",
    "google_app_id",
    "gcm_defaultsendersid",
    "google_api_key",
    "current_key",
    "google-services",
    "google_services",
    "default_web_client_id",
    "firebase_database_url",
    "firebaseio.com",
)

# Maps / geo co-location markers for AIza keys.
_MAPS_CONTEXT_MARKERS = (
    "maps",
    "geo",
    "location",
    "places",
    "directions",
    "geocod",
    "streetview",
)

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Minimum Shannon entropy an ``Authorization: Basic`` credential must have to be
# treated as genuine base64 credentials rather than a plain word/UI phrase.
_BASIC_AUTH_MIN_ENTROPY = 3.0


@dataclass
class SecretVerdict:
    """Outcome of validating a single regex match.

    Attributes:
        rejected: When True the match must be discarded (false positive / binary).
        severity: Possibly re-classified severity ("CRITICAL"/"HIGH"/"MEDIUM"/
            "LOW"), or None to keep the pattern's original severity.
        confidence: 0.0-1.0 confidence the match is a genuine secret.
        classification_label: Human-readable risk label (e.g. "client-side key
            (safe by design)") or None.
        classification_basis: Why the classification was chosen (e.g.
            "allowlist:public_client", "co_location:firebase", "prefix_only",
            "structural", "generic:gated"). A "prefix_only" basis may not push a
            restriction_dependent key below its MEDIUM floor.
    """

    rejected: bool = False
    severity: str | None = None
    confidence: float = 0.0
    classification_label: str | None = None
    classification_basis: str | None = None
    reason: str | None = None


class SecretValidator:
    """Validate/reclassify secret matches for precision AND recall.

    Constructed from the assessment's threshold configuration so the ``dexray.yaml``
    knobs (entropy thresholds, min-confidence, allowlist/binary/JWT toggles) reach
    the active detection path.
    """

    def __init__(
        self,
        entropy_thresholds: dict[str, float] | None = None,
        length_filters: dict[str, int] | None = None,
        context_detection_enabled: bool = True,
        context_strict_mode: bool = False,
        key_detection_config: dict[str, Any] | None = None,
        logger: logging.Logger | None = None,
    ):
        self.logger = logger or logging.getLogger(__name__)

        self.entropy_thresholds = entropy_thresholds or {
            "min_base64_entropy": 4.0,
            "min_hex_entropy": 3.5,
            "min_generic_entropy": 5.0,
        }
        self.length_filters = length_filters or {"min_key_length": 16, "max_key_length": 512}
        self.context_detection_enabled = context_detection_enabled
        self.context_strict_mode = context_strict_mode

        cfg = key_detection_config or {}
        confidence_cfg = cfg.get("confidence", {})
        self.confidence_enabled = confidence_cfg.get("enabled", True)
        self.min_confidence = float(confidence_cfg.get("min_confidence", 0.0))

        allowlist_cfg = cfg.get("allowlist", {})
        self.allowlist_enabled = allowlist_cfg.get("enabled", True)

        binary_cfg = cfg.get("binary_filter", {})
        self.binary_filter_enabled = binary_cfg.get("enabled", True)

        jwt_cfg = cfg.get("jwt", {})
        self.jwt_require_decodable_header = jwt_cfg.get("require_decodable_header", True)

        self._allowlist_entries: list[dict[str, Any]] = self._load_allowlist()

    # ------------------------------------------------------------------ loading
    def _load_allowlist(self) -> list[dict[str, Any]]:
        """Load the known-safe-credentials registry (best-effort)."""
        path = Path(__file__).parent / "data" / "known_safe_credentials.yaml"
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            entries = data.get("entries", []) or []
            return [e for e in entries if isinstance(e, dict)]
        except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - defensive
            self.logger.debug(f"Could not load known_safe_credentials.yaml: {exc}")
            return []

    # ---------------------------------------------------------------- public API
    def evaluate(
        self,
        matched_value: str,
        full_context: str,
        pattern_name: str,
        pattern_config: dict[str, Any],
    ) -> SecretVerdict:
        """Validate a single match and return a :class:`SecretVerdict`.

        Args:
            matched_value: The captured secret value (capture group if present,
                otherwise the whole match).
            full_context: The complete source string the match was found in.
            pattern_name: Name of the detection pattern that matched.
            pattern_config: The pattern's configuration dict.
        """
        base_severity = pattern_config.get("severity", "MEDIUM")
        is_generic = pattern_name in GENERIC_PATTERN_NAMES

        # 1. JWT header gate (targeted validator; applies to the jwt_token pattern).
        if pattern_name == "jwt_token":
            return self._evaluate_jwt(matched_value, base_severity)

        # 1b. HTTP Basic authorization gate (targeted validator). ``authorization_basic``
        #     is structural, so without this a plain UI string like "basic settings"
        #     would skip every gate and be reported as a HIGH secret.
        if pattern_name == "authorization_basic":
            return self._evaluate_authorization_basic(matched_value, base_severity)

        # 2. Binary-signature rejection. Real prefix keys never base64-decode to a
        #    full binary signature, so running this for structural matches too is
        #    safe and catches e.g. an image blob that matched a Square-token shape.
        #    The check runs on BOTH the matched fragment AND the full source string:
        #    a structural prefix token (e.g. an ``EAAA...`` Square-token shape) can be
        #    a ~64-char slice of a larger base64 image blob whose PNG magic (offset 0)
        #    or ICC 'acsp' marker (offset 36) only aligns on the FULL string.
        if self.binary_filter_enabled:
            binary = self._binary_verdict(matched_value)
            if binary is None and full_context and full_context != matched_value:
                binary = self._binary_verdict(full_context)
            if binary is not None:
                return binary

        # 3. Structural vs generic split.
        if not is_generic:
            return self._evaluate_structural(matched_value, full_context, pattern_name, pattern_config, base_severity)
        return self._evaluate_generic(matched_value, full_context, pattern_name, pattern_config, base_severity)

    # --------------------------------------------------------------- structural
    def _evaluate_structural(
        self,
        matched_value: str,
        full_context: str,
        pattern_name: str,
        pattern_config: dict[str, Any],
        base_severity: str,
    ) -> SecretVerdict:
        """Structural keys skip entropy/context/FP gating; only class reclassification runs."""
        entry = self._match_allowlist(matched_value, pattern_name)
        if entry is not None:
            return self._verdict_from_allowlist(entry, full_context, base_severity)

        # Structural but unknown class: keep the pattern's severity, high confidence.
        return SecretVerdict(
            rejected=False,
            severity=None,
            confidence=0.9,
            classification_label=None,
            classification_basis="structural",
        )

    def _verdict_from_allowlist(
        self, entry: dict[str, Any], full_context: str, base_severity: str
    ) -> SecretVerdict:
        cls = entry.get("class")
        label = entry.get("label")

        if cls == "public_client":
            # Client-side key: safe by design -> LOW (downrank allowed).
            return SecretVerdict(
                rejected=False,
                severity=entry.get("severity", "LOW"),
                confidence=0.9,
                classification_label=label or "client-side key (safe by design)",
                classification_basis="allowlist:public_client",
            )

        if cls == "private_secret":
            # Allowlist may NEVER downgrade a private secret: keep the higher of
            # the entry severity and the pattern's own severity.
            entry_sev = entry.get("severity", "HIGH")
            severity = self._max_severity(entry_sev, base_severity)
            return SecretVerdict(
                rejected=False,
                severity=severity,
                confidence=0.95,
                classification_label=label or "server-side secret",
                classification_basis="allowlist:private_secret",
            )

        if cls == "restriction_dependent":
            return self._verdict_restriction_dependent(entry, full_context)

        # Unknown class: treat as plain structural.
        return SecretVerdict(rejected=False, severity=None, confidence=0.9, classification_basis="structural")

    def _verdict_restriction_dependent(self, entry: dict[str, Any], full_context: str) -> SecretVerdict:
        """MEDIUM floor, never suppressed; severity refined by co-location context.

        A ``prefix_only`` basis may not push the key below the MEDIUM floor.
        """
        note = entry.get("note", "verify restrictions")
        label = entry.get("label") or f"API key ({note})"
        lowered = full_context.lower()

        if any(marker in lowered for marker in _FIREBASE_CONTEXT_MARKERS):
            return SecretVerdict(
                rejected=False,
                severity="LOW",
                confidence=0.85,
                classification_label=label,
                classification_basis="co_location:firebase",
            )
        if any(marker in lowered for marker in _MAPS_CONTEXT_MARKERS):
            return SecretVerdict(
                rejected=False,
                severity="MEDIUM",
                confidence=0.85,
                classification_label=label,
                classification_basis="co_location:maps",
            )
        # Bare key: only the prefix is known -> MEDIUM floor, never suppressed.
        return SecretVerdict(
            rejected=False,
            severity="MEDIUM",
            confidence=0.8,
            classification_label=label,
            classification_basis="prefix_only",
        )

    # ------------------------------------------------------------------ generic
    def _evaluate_generic(
        self,
        matched_value: str,
        full_context: str,
        pattern_name: str,
        pattern_config: dict[str, Any],
        base_severity: str,
    ) -> SecretVerdict:
        """Full gate for prefix-less generic patterns.

        Hard gates that MAY drop (tunable knobs): min-entropy, max-length,
        min-confidence. Soft signals (missing context, FP heuristics) never drop a
        hit that clears the length guard -- they downgrade it to LOW and log, so a
        genuine prefix-less secret still surfaces.
        """
        # Length guard (hard).
        max_length = pattern_config.get("max_length") or self.length_filters.get("max_key_length", 512)
        if max_length and len(matched_value) > max_length:
            return SecretVerdict(rejected=True, reason="exceeds max length", classification_basis="generic:length")

        # Entropy gate (hard, tunable via dexray.yaml).
        min_entropy = self._resolve_min_entropy(pattern_name, pattern_config)
        entropy = self._entropy(matched_value)
        if min_entropy and entropy < min_entropy:
            return SecretVerdict(
                rejected=True,
                reason=f"entropy {entropy:.2f} < {min_entropy}",
                classification_basis="generic:entropy",
            )

        # Soft signals: never drop, only downgrade.
        downgraded = False
        basis = "generic:gated"

        context_required = pattern_config.get("context_required", [])
        if context_required and self.context_detection_enabled and not self._has_context(full_context, context_required):
            # ``context_hard`` patterns (e.g. bare hex keys) HARD-DROP without context:
            # entropy cannot separate a crypto known-answer-test vector from a real
            # key, so context is the only discriminator. Global strict_mode still
            # forces the same hard drop for every context-required pattern.
            if self.context_strict_mode or pattern_config.get("context_hard"):
                return SecretVerdict(rejected=True, reason="missing required context", classification_basis="generic:context")
            downgraded = True
            basis = "generic:no_context"
            self.logger.debug(f"Generic hit '{pattern_name}' lacks required context; downgraded to LOW")

        fp_probability = self._false_positive_probability(matched_value)
        # base64/entropy "leakage" family: a path-like URL/class-package fragment
        # (``com/library/test/success``), a Smali/DEX class descriptor
        # (``Lcom/revenuecat/purchases/Offerings``), or a long camelCase/PascalCase
        # Java identifier (``findTrustAnchorByIssuerAndSignature``,
        # ``BadgeCountFileDescriptorSupplier``) is noise, not a secret. These match
        # ``high_entropy_string`` AND ``base64_key_long``/``base64_key_medium`` on
        # real APKs, so the drop must cover the whole family -> hard drop instead of
        # the soft LOW downgrade that produced tens of thousands of "Information
        # Leakage" entries. Genuine high-entropy base64 secrets (containing '+'/'='
        # or lacking identifier-path/word structure) are NOT matched by these
        # helpers and survive.
        if pattern_name in _PATH_DROP_PATTERN_NAMES and (
            self._looks_like_path(matched_value)
            or self._looks_like_dex_descriptor(matched_value)
            or self._looks_like_code_identifier(matched_value)
        ):
            return SecretVerdict(
                rejected=True,
                reason="path-like / DEX class-descriptor / code-identifier noise (not a secret)",
                classification_basis="generic:path_fp",
            )
        # high_entropy_string retains its broader FP drop (mostly-digit ids, dotted
        # class names, obvious placeholders) — path-like hits are already handled above.
        if pattern_name == "high_entropy_string" and fp_probability >= 0.5:
            return SecretVerdict(
                rejected=True,
                reason=f"high-entropy noise (path-like/FP p={fp_probability:.2f})",
                classification_basis="generic:path_fp",
            )
        if fp_probability >= 0.5:
            downgraded = True
            basis = "generic:false_positive"
            self.logger.debug(f"Generic hit '{pattern_name}' looks like a false positive (p={fp_probability:.2f})")

        # Confidence = f(entropy, context) - fp_probability.
        confidence = self._generic_confidence(entropy, min_entropy or 4.0, not downgraded, fp_probability)

        # Confidence floor (hard, tunable via dexray.yaml).
        if self.confidence_enabled and confidence < self.min_confidence:
            return SecretVerdict(
                rejected=True,
                reason=f"confidence {confidence:.2f} < {self.min_confidence}",
                classification_basis="generic:confidence",
            )

        severity = "LOW" if downgraded else None
        return SecretVerdict(
            rejected=False,
            severity=severity,
            confidence=confidence,
            classification_label=None,
            classification_basis=basis,
        )

    # -------------------------------------------------------------------- JWT
    def _evaluate_jwt(self, matched_value: str, base_severity: str) -> SecretVerdict:
        """Validate a JWT/JWE by its HEADER only.

        Accepts 2/3/5 dot-separated segments (JWE has 5; ``alg:none`` leaves an
        empty signature). Requires the literal ``eyJ`` prefix, a base64url-decodable
        first segment, valid JSON, and an ``alg`` field. The payload is never parsed
        and ``exp`` is never checked.
        """
        if not self.jwt_require_decodable_header:
            return SecretVerdict(rejected=False, severity=None, confidence=0.7, classification_basis="jwt:unchecked")

        if not matched_value.startswith("eyJ"):
            return SecretVerdict(rejected=True, reason="no eyJ prefix", classification_basis="jwt:no_prefix")

        segments = matched_value.split(".")
        if len(segments) not in (2, 3, 5):
            return SecretVerdict(rejected=True, reason="bad segment count", classification_basis="jwt:segments")

        header_seg = segments[0]
        if not _JWT_SEGMENT_RE.match(header_seg):
            return SecretVerdict(rejected=True, reason="non-base64url header", classification_basis="jwt:header")

        decoded = self._b64url_decode(header_seg)
        if decoded is None:
            return SecretVerdict(rejected=True, reason="undecodable header", classification_basis="jwt:header")

        try:
            header = json.loads(decoded)
        except (ValueError, UnicodeDecodeError):
            return SecretVerdict(rejected=True, reason="header not JSON", classification_basis="jwt:header")

        if not isinstance(header, dict) or "alg" not in header:
            return SecretVerdict(rejected=True, reason="header missing alg", classification_basis="jwt:header")

        return SecretVerdict(
            rejected=False,
            severity=base_severity,
            confidence=0.9,
            classification_label="JWT (valid header)",
            classification_basis="jwt:valid_header",
        )

    # ------------------------------------------------------ authorization basic
    def _evaluate_authorization_basic(self, matched_value: str, base_severity: str) -> SecretVerdict:
        """Validate an ``Authorization: Basic`` match by its credential shape.

        HTTP Basic credentials are ``base64(user:password)`` — a compact, mixed
        alphabet, no whitespace. A plain UI phrase such as ``"basic settings"``
        matches the pattern but is obviously not a credential. Rejection signals
        (any one is enough), kept deliberately conservative so a genuine base64
        blob still surfaces:

        * the credential contains whitespace (multi-word phrase);
        * the credential is a single lowercase dictionary-style word (``settings``);
        * the credential's Shannon entropy is below :data:`_BASIC_AUTH_MIN_ENTROPY`.
        """
        match = re.match(r"(?is)basic\s+(.+)$", matched_value.strip())
        credential = (match.group(1) if match else matched_value).strip()

        reason: str | None = None
        if not credential or re.search(r"\s", credential):
            reason = "basic-auth credential contains whitespace (UI phrase, not creds)"
        elif re.fullmatch(r"[A-Za-z]+", credential) and credential.islower():
            reason = "basic-auth value is a plain lowercase word, not base64 credentials"
        elif self._entropy(credential) < _BASIC_AUTH_MIN_ENTROPY:
            reason = f"basic-auth credential entropy {self._entropy(credential):.2f} too low"

        if reason is not None:
            return SecretVerdict(rejected=True, reason=reason, classification_basis="authorization_basic:fp")

        return SecretVerdict(
            rejected=False,
            severity=base_severity,
            confidence=0.85,
            classification_label="HTTP Basic credentials",
            classification_basis="authorization_basic:valid",
        )

    # ---------------------------------------------------------------- binary
    def _binary_verdict(self, value: str) -> SecretVerdict | None:
        """Return a rejecting verdict if ``value`` base64-decodes to a binary blob.

        Only rejects on a FULL known signature (or a genuinely successful zlib
        decompress). A 2-byte zlib-header collision is too likely, so zlib requires
        an actual ``zlib.decompress`` success. Returns None when nothing matched.
        """
        # Must plausibly be base64 to bother decoding.
        stripped = value.strip()
        if len(stripped) < 16 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
            return None

        raw = self._b64_decode(stripped)
        if raw is None or len(raw) < 4:
            return None

        label = self._identify_binary(raw)
        if label is not None:
            return SecretVerdict(
                rejected=True,
                reason=f"base64 decodes to {label}",
                classification_basis="binary_blob",
            )
        return None

    @staticmethod
    def _b64_decode(value: str) -> bytes | None:
        """Standard base64 decode with padding repair; None on failure."""
        try:
            padded = value + "=" * (-len(value) % 4)
            return base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return None

    @staticmethod
    def _b64url_decode(value: str) -> bytes | None:
        """base64url decode with padding repair; None on failure."""
        try:
            padded = value + "=" * (-len(value) % 4)
            return base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError):
            return None

    @staticmethod
    def _identify_binary(raw: bytes) -> str | None:
        """Identify a decoded byte blob by a full magic signature."""
        if raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG image"
        if raw.startswith(b"\xff\xd8\xff"):
            return "JPEG image"
        if raw.startswith(b"GIF8"):
            return "GIF image"
        if raw.startswith(b"%PDF"):
            return "PDF document"
        if raw.startswith(b"PK\x03\x04"):
            return "ZIP archive"
        if raw.startswith(b"\x7fELF"):
            return "ELF binary"
        # ICC colour profile: 'acsp' signature at byte offset 36.
        if len(raw) >= 40 and raw[36:40] == b"acsp":
            return "ICC profile"
        # zlib: only reject on a genuinely successful decompress (header collisions
        # with real keys are otherwise far too likely).
        if len(raw) >= 2 and raw[0] == 0x78 and raw[1] in (0x01, 0x9C, 0xDA, 0x5E):
            try:
                zlib.decompress(raw)
                return "zlib stream"
            except zlib.error:
                return None
        return None

    # ----------------------------------------------------------- allowlist match
    def _match_allowlist(self, matched_value: str, pattern_name: str) -> dict[str, Any] | None:
        """Find the allowlist entry for a match (by prefix or pattern name)."""
        if not self.allowlist_enabled:
            return None
        for entry in self._allowlist_entries:
            prefix = entry.get("prefix")
            if prefix and matched_value.startswith(prefix):
                return entry
            if entry.get("pattern_name") == pattern_name:
                return entry
        return None

    # -------------------------------------------------------------- small helpers
    def _resolve_min_entropy(self, pattern_name: str, pattern_config: dict[str, Any]) -> float:
        """Effective min-entropy for a generic hit.

        The configurable per-type threshold from ``dexray.yaml`` acts as a global
        FLOOR; a pattern's own ``min_entropy`` may only raise it. This keeps the
        default behaviour (config == pattern threshold) while ensuring that cranking
        a dexray.yaml entropy knob actually tightens the active detection path.
        """
        if "base64" in pattern_name:
            configured = self.entropy_thresholds.get("min_base64_entropy", 4.0)
        elif "hex" in pattern_name:
            configured = self.entropy_thresholds.get("min_hex_entropy", 3.5)
        else:
            configured = self.entropy_thresholds.get("min_generic_entropy", 5.0)

        explicit = pattern_config.get("min_entropy")
        if explicit is not None:
            return max(float(explicit), float(configured))
        return float(configured)

    @staticmethod
    def _entropy(string: str) -> float:
        if not string:
            return 0.0
        counter = Counter(string)
        length = len(string)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def _has_context(full_context: str, required_keywords: list[str]) -> bool:
        lowered = full_context.lower()
        return any(keyword.lower() in lowered for keyword in required_keywords)

    @staticmethod
    def _max_severity(a: str, b: str) -> str:
        return a if _SEVERITY_RANK.get(a, 1) >= _SEVERITY_RANK.get(b, 1) else b

    @staticmethod
    def _generic_confidence(entropy: float, min_entropy: float, has_context: bool, fp_probability: float) -> float:
        """Confidence for a generic hit: f(entropy, context) - fp_probability."""
        # Normalise entropy over [min_entropy, 6.0] (6 ~ max for base64 charset).
        span = max(6.0 - min_entropy, 0.5)
        entropy_score = max(0.0, min(1.0, (entropy - min_entropy) / span))
        base = 0.4 + 0.4 * entropy_score
        if has_context:
            base += 0.2
        return max(0.0, min(1.0, base - fp_probability))

    def _false_positive_probability(self, value: str) -> float:
        """Small, local FP-probability heuristic (0-1).

        Deliberately self-contained: does NOT import the dormant
        ``context_analysis.FalsePositiveFilter`` (wired separately in PR-7).
        """
        if not value:
            return 1.0
        lowered = value.lower()
        length = len(value)

        # Obvious non-secret shapes.
        obvious_fp = (
            r"^(com|android|java|javax|kotlin|androidx)\.",
            r"^(test|example|sample|demo|placeholder|dummy|fake|mock|stub)",
            r"^(your_|insert_|replace_with|api_key_here)",
            r"^(null|undefined|none|nil|empty|true|false)$",
            r"^https?://",
            r"^(.)\1{10,}$",
        )
        for pat in obvious_fp:
            if re.search(pat, lowered):
                return 0.9

        # Mostly digits (ids, timestamps).
        if length > 8 and sum(c.isdigit() for c in value) / length > 0.8:
            return 0.7

        # Dotted identifier / class-name shapes (e.g. BouncyCastle
        # keyPairGenerator.SPHINCS256): alphanumeric words joined by dots, no base64
        # punctuation. These are code references, not secrets.
        if "." in value and re.fullmatch(r"[A-Za-z][A-Za-z0-9_$]*(?:\.[A-Za-z][A-Za-z0-9_$]*)+", value):
            return 0.6

        # Slash-delimited path fragments (URL / class-package paths such as
        # ``com/library/test/success`` or ``net/sdk/sdk/1121/android/mraid``). These
        # match the high-entropy shape but are navigation/library paths, not keys.
        # base64 punctuation ('+'/'=') is absent from such paths, so its presence
        # rules out this branch and protects genuine base64 secrets.
        if self._looks_like_path(value):
            return 0.9

        return 0.05

    @staticmethod
    def _looks_like_path(value: str) -> bool:
        """True for slash-delimited path fragments (URL/class-package paths).

        Requires >=2 non-empty segments, most of which are short identifier-like
        tokens containing a letter, and no base64 padding/plus punctuation (which
        would indicate a genuine base64 blob rather than a path).
        """
        if "/" not in value or "+" in value or "=" in value:
            return False
        segments = [seg for seg in value.split("/") if seg]
        if len(segments) < 2:
            return False
        id_like = [
            seg
            for seg in segments
            if len(seg) <= 40 and re.fullmatch(r"[A-Za-z0-9_$.-]+", seg) and re.search(r"[A-Za-z]", seg)
        ]
        return len(id_like) >= 2 and len(id_like) >= len(segments) - 1

    @staticmethod
    def _looks_like_dex_descriptor(value: str) -> bool:
        """True for a Smali/DEX class type descriptor.

        A DEX/Smali class descriptor is ``L`` followed by slash-separated identifier
        segments, optionally with a trailing ``;`` (e.g. ``Lcom/revenuecat/purchases/
        Offerings`` or ``Landroidx/compose/ui/text/SaversKt;``). ``_looks_like_path``
        already covers the multi-segment shape, but this catches the 2-segment /
        trailing-``;`` edge cases it would otherwise miss.
        """
        return bool(
            re.fullmatch(
                r"L(?:[A-Za-z_$][A-Za-z0-9_$]*/)+[A-Za-z_$][A-Za-z0-9_$]*;?",
                value,
            )
        )

    @staticmethod
    def _looks_like_code_identifier(value: str) -> bool:
        """True for a long camelCase/PascalCase source-code identifier.

        Java method and class names such as ``findTrustAnchorByIssuerAndSignature``
        or ``BadgeCountFileDescriptorSupplier`` have no slash, so they escape
        ``_looks_like_path``/``_looks_like_dex_descriptor`` yet still match the
        prefix-less ``base64_key_medium`` shape (``[A-Za-z0-9+/=]{20,}``) and
        dominated the LOW "Information Leakage" bucket. They are source code, never
        secrets. A string qualifies as an identifier (-> drop) ONLY when ALL hold:

        * it is purely ``[A-Za-z0-9]`` -- ANY base64 padding/special char
          (``+``/``/``/``=``) means it is NOT an identifier and is left alone. This
          is the key guardrail protecting genuine base64 tokens such as
          ``gfLiyhD2OvLSOj6bwf+kcmK11rwQ90aeBshxHD6xXgk=``;
        * it is a valid identifier shape (starts with a letter);
        * it is not dominated by digits (numeric ids/timestamps are handled
          elsewhere);
        * it decomposes into camelCase/PascalCase words: at least two
          dictionary-length word tokens (a run of >=3 letters, optionally
          capital-led) that together cover most of the string. A random
          high-entropy alnum blob (e.g. ``A1b2C3d4E5f6...`` with single-letter
          case flips) has no such word runs, so it is NOT classified here and the
          entropy/other gates decide it.
        """
        if not value or not re.fullmatch(r"[A-Za-z0-9]+", value):
            return False
        if not value[0].isalpha():
            return False
        digit_count = sum(c.isdigit() for c in value)
        if digit_count / len(value) >= 0.5:
            return False
        words = [w for w in _CODE_WORD_RE.findall(value) if len(w) >= 3]
        if len(words) < 2:
            return False
        covered = sum(len(w) for w in words)
        return covered / len(value) >= 0.6
