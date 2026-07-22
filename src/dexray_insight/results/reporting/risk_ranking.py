#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
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

"""Pure ranking / tiering primitives for security-finding triage reporting.

This module is deliberately I/O-free and dependency-free. It operates uniformly
on *findings*, where a finding may be either:

* a plain ``dict`` (the serialized shape produced by ``SecurityFinding.to_dict``), or
* a ``SecurityFinding`` (or any object exposing the same attributes).

All access goes through :func:`get_attr`, a safe getter that transparently reads
either dictionary keys or object attributes. Consequently every function here can
be unit-tested with light-weight dicts while still working on live objects in the
report path.

The single "value" axis used for ranking is ``severity_weight × confidence`` — the
same shape the evidence-weighted risk scorer uses (see ``core/security_engine``),
so the report's ordering agrees with the headline risk score.
"""

from __future__ import annotations

from typing import Any

# Severity impact weights. Mirrors ``SecurityAssessmentEngine._SEVERITY_WEIGHTS``
# so report ranking and the headline risk score never disagree on relative impact.
SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

# Confidence assumed when a finding carries none. 0.6 keeps an unscored finding
# above a low-confidence heuristic (0.2-0.4) but below a confirmed one (>=0.75).
DEFAULT_CONFIDENCE: float = 0.6

# Tier threshold defaults. Overridable via config (output.security_report.tiers).
DEFAULT_HIGH_CONFIDENCE_MIN: float = 0.75
DEFAULT_REVIEW_MIN: float = 0.40

# Concrete "why this matters / next step" hints keyed by a substring of the
# finding's OWASP category. First match wins; falls back to the finding's own
# first recommendation, then to a generic prompt.
CATEGORY_HINTS: dict[str, str] = {
    "A01": "Attacker-reachable component — verify export/permission intent and lock down access.",
    "A02": "Weak or hard-coded cryptographic material — rotate the secret and move to a keystore.",
    "A03": "Untrusted input can reach a sensitive sink — parameterize queries / validate input.",
    "A04": "Design-level weakness — review the threat model for this flow.",
    "A05": "Misconfiguration weakens the app's security posture — harden the manifest/config.",
    "A06": "Outdated / vulnerable component — upgrade to a patched release.",
    "A07": "Authentication / session weakness — review credential and session handling.",
    "A08": "Integrity / deserialization risk — validate and sign data before trusting it.",
    "A09": "Logging exposes sensitive data or hides attacks — scrub logs and add monitoring.",
    "A10": "Server-side request risk — validate and allowlist outbound request targets.",
    "injection": "Untrusted input can reach a sensitive sink — parameterize queries / validate input.",
    "cryptographic": "Weak or hard-coded cryptographic material — rotate the secret and move to a keystore.",
    "sensitive data": "Sensitive value exposed in the package — remove or protect it.",
    "hard-coded": "Rotate this credential and load it from a secure store at runtime.",
    "secret": "Rotate this credential and load it from a secure store at runtime.",
    "access control": "Attacker-reachable component — verify export/permission intent and lock down access.",
    "misconfiguration": "Misconfiguration weakens the app's security posture — harden the manifest/config.",
    "webview": "WebView JS bridge widens the attack surface — restrict interfaces and validate content.",
    "deep-link": "Exported deep-link entry point — validate incoming URIs and enforce permissions.",
    "cleartext": "Traffic sent in cleartext — enforce HTTPS / a network-security config.",
    "vulnerable": "Outdated / vulnerable component — upgrade to a patched release.",
    "cve": "Known vulnerability in a bundled component — upgrade to a patched release.",
}


def get_attr(finding: Any, name: str, default: Any = None) -> Any:
    """Safely read ``name`` from a finding that is a dict OR an object.

    For dicts this is ``finding.get(name, default)``. For objects it returns the
    attribute value (never calling it), falling back to ``default`` when the
    attribute is absent or ``None``.
    """
    value = finding.get(name, default) if isinstance(finding, dict) else getattr(finding, name, default)
    return default if value is None else value


def severity_str(finding: Any) -> str:
    """Coerce a finding's severity (enum | ``{'value': ...}`` | str) to lower-case."""
    severity = get_attr(finding, "severity", "unknown")
    if isinstance(severity, dict) and "value" in severity:
        severity = severity["value"]
    severity_text = severity.value if hasattr(severity, "value") else str(severity)
    return severity_text.lower()


def confidence_of(finding: Any) -> float:
    """Return the finding's confidence as a float, defaulting to :data:`DEFAULT_CONFIDENCE`."""
    confidence = get_attr(finding, "confidence", None)
    if confidence is None:
        return DEFAULT_CONFIDENCE
    try:
        return float(confidence)
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE


def verification_status_of(finding: Any) -> str:
    """Coerce a finding's verification_status (enum | serialized str | absent) to lower-case.

    Absent/None normalizes to ``"confirmed"`` so pre-existing findings (and any producer
    that does not set the field) keep their prior "confirmed" behavior. Mirrors the engine's
    ``_confirmed_subset`` semantics so the report's tiering agrees with the headline score.
    """
    status = get_attr(finding, "verification_status", "confirmed")
    status_text = status.value if hasattr(status, "value") else str(status)
    return status_text.lower()


def has_location(finding: Any) -> bool:
    """Whether the finding carries a concrete file location (dict or object shape)."""
    return bool(get_attr(finding, "file_location", None) or get_attr(finding, "fileLocation", None))


def title_of(finding: Any) -> str:
    """Return the finding's title as a string (empty when absent)."""
    return str(get_attr(finding, "title", "") or "")


def finding_score(finding: Any) -> float:
    """Compute the ranking value: ``severity_weight × confidence``.

    Confidence falls back to :data:`DEFAULT_CONFIDENCE` when the finding is unscored.
    """
    weight = SEVERITY_WEIGHT.get(severity_str(finding), 0)
    return weight * confidence_of(finding)


def _rank_key(finding: Any) -> tuple:
    """Descending ranking key: (score, has_location, title).

    A concrete file location breaks score ties (locatable findings are more
    actionable); the title is the final deterministic tie-breaker.
    """
    return (finding_score(finding), 1 if has_location(finding) else 0, title_of(finding))


def rank_findings(findings: list) -> list:
    """Return findings sorted by descending value; stable and deterministic.

    Ordering is by ``(score, has_location, title)`` descending. ``sorted`` is stable,
    so findings identical on all three keys retain their original relative order.
    """
    if not findings:
        return []
    return sorted(findings, key=_rank_key, reverse=True)


def top_risks(findings: list, n: int = 5) -> list:
    """Return the top ``n`` findings by descending value."""
    if n <= 0:
        return []
    return rank_findings(findings)[:n]


def _resolve_thresholds(config: Any) -> tuple[float, float]:
    """Extract (high_confidence_min, review_min) from a config of several shapes.

    Accepts ``None``, a Configuration object (``get_output_config``), the ``output``
    dict, the ``security_report`` dict, or a bare ``tiers`` dict. Missing values
    fall back to the module defaults.
    """
    high_min = DEFAULT_HIGH_CONFIDENCE_MIN
    review_min = DEFAULT_REVIEW_MIN

    tiers: dict = {}
    if config is None:
        tiers = {}
    elif hasattr(config, "get_output_config"):
        tiers = (config.get_output_config().get("security_report", {}) or {}).get("tiers", {}) or {}
    elif isinstance(config, dict):
        # Progressively unwrap: output -> security_report -> tiers.
        node = config
        if "output" in node and isinstance(node["output"], dict):
            node = node["output"]
        if "security_report" in node and isinstance(node["security_report"], dict):
            node = node["security_report"]
        if "tiers" in node and isinstance(node["tiers"], dict):
            tiers = node["tiers"]
        else:
            tiers = node if ("high_confidence_min" in node or "review_min" in node) else {}

    if isinstance(tiers, dict):
        high_min = float(tiers.get("high_confidence_min", high_min))
        review_min = float(tiers.get("review_min", review_min))
    return high_min, review_min


def tier_findings(findings: list, config: Any = None) -> dict[str, list]:
    """Partition findings into triage tiers for tiered reporting.

    Tiers (thresholds from ``config``, defaulting to 0.75 / 0.40):

    * ``confirmed`` — ``verification_status == CONFIRMED`` AND confidence >=
      ``high_confidence_min`` AND severity in {critical, high}. These are the
      statically-decidable "act now" findings, matching the engine's confirmed subset.
    * ``needs_review`` — ``review_min`` <= confidence < ``high_confidence_min``,
      OR any medium-severity finding, OR any NEEDS_DYNAMIC / NEEDS_REVIEW finding
      (regardless of confidence/severity — exploitability is unconfirmed). Worth a human look.
    * ``informational`` — confidence < ``review_min``, or info/unknown severity
      noise. Hidden by default in the terminal.

    Returns a dict with keys ``confirmed``, ``needs_review`` and ``informational``,
    each a value-ranked list. Every finding lands in exactly one tier.
    """
    high_min, review_min = _resolve_thresholds(config)

    confirmed: list = []
    needs_review: list = []
    informational: list = []

    for finding in findings:
        severity = severity_str(finding)
        confidence = confidence_of(finding)
        # A review-queue finding (NEEDS_DYNAMIC / NEEDS_REVIEW) is never "confirmed" in the
        # report, even at high confidence — its exploitability is not statically settled.
        # This keeps the report's CONFIRMED tier in lockstep with the engine's headline
        # confirmed subset (see SecurityAssessmentEngine._confirmed_subset).
        is_confirmed_status = verification_status_of(finding) == "confirmed"

        if is_confirmed_status and confidence >= high_min and severity in ("critical", "high"):
            confirmed.append(finding)
        elif severity in ("critical", "high", "medium") and confidence >= review_min:
            needs_review.append(finding)
        elif severity == "medium":
            # Medium below review_min still warrants a look rather than being buried.
            needs_review.append(finding)
        else:
            informational.append(finding)

    return {
        "confirmed": rank_findings(confirmed),
        "needs_review": rank_findings(needs_review),
        "informational": rank_findings(informational),
    }


def hint_for(finding: Any) -> str:
    """Return a one-line "why this matters / next step" hint for a finding.

    Prefers a category-keyed hint (matched case-insensitively against the OWASP
    category), then the finding's first recommendation, then a generic prompt.
    """
    category = str(get_attr(finding, "category", "") or "")
    category_lower = category.lower()
    for key, hint in CATEGORY_HINTS.items():
        if key.lower() in category_lower:
            return hint

    recommendations = get_attr(finding, "recommendations", []) or []
    if isinstance(recommendations, (list, tuple)) and recommendations:
        return str(recommendations[0])
    if isinstance(recommendations, str) and recommendations:
        return recommendations

    return "Review this finding and confirm whether it is exploitable in context."
