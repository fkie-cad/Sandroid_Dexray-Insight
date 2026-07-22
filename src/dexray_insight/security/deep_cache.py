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

"""Findings-level cache for the expensive DEEP (``--deep``) assessments (Phase C4).

The two deep assessments — ``deep_dataflow`` and ``pii_flow`` — each build the
androguard cross-reference graph via ``create_xref()``, which dominates the cost
of a deep run. This module caches their *findings* (as ``SecurityFinding``
dicts) keyed by ``(apk_md5, assessment_name, config_hash)`` so that a re-run on
the same APK deserializes the prior result and returns WITHOUT touching
androguard — ``create_xref()`` is never rebuilt on a cache hit.

The wrapper is deliberately thin and lives at the assessment boundary: the
detection logic inside each assessment is untouched. It also degrades
gracefully — when no cache manager or APK md5 is available (e.g. unit tests,
callers that never wired the cache), it just runs the build function.

Staleness is handled by :class:`AnalysisCacheManager`'s fingerprint validation:
the cache is invalidated automatically whenever the dexray-insight version, the
androguard version, or the cache schema changes. The findings are a
deterministic function of (APK bytes, tool versions, assessment config), and all
three participate in the key/fingerprint, so a stale hit is not possible without
one of those inputs changing.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import FileLocation
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus

logger = logging.getLogger(__name__)

# Version stamp for the DEEP detector LOGIC + finding schema. The cache key is
# derived only from (apk_md5, module, config_hash), and config_hash is fingerprinted
# on tool/androguard/schema versions — none of which change when detector logic is
# edited without a package version bump. Folding this constant into the config_hash
# means any detector-logic revision (bump the suffix) changes the key, so a stale
# HIT can never serve findings from the old logic. Bump on ANY logic/schema change.
DEEP_SCHEMA_VERSION = "c1-v3"

# Fallback config hash used when the cache manager's ``hash_config`` helper is
# unavailable. Constant per schema version — bump the suffix if the finding
# serialization format changes in a backwards-incompatible way.
_FALLBACK_CONFIG_HASH = "deep_v1"


def _config_hash(config: Any) -> str:
    """Return a stable hash of the assessment config, tolerating import failure.

    The active :data:`DEEP_SCHEMA_VERSION` is folded into the hashed input so a
    detector-logic revision (which does not change the APK bytes or tool versions)
    still produces a different cache key and cannot serve stale findings.
    """
    keyed = {"deep_schema_version": DEEP_SCHEMA_VERSION, "config": config}
    try:
        from ..core.cache_manager import hash_config

        return hash_config(keyed)
    except Exception:
        return f"{_FALLBACK_CONFIG_HASH}:{DEEP_SCHEMA_VERSION}"


def cached_deep_findings(
    context: Any,
    module_name: str,
    config: Any,
    build_fn: Callable[[], list[SecurityFinding]],
) -> list[SecurityFinding]:
    """Return cached deep-assessment findings, or compute + cache them on a miss.

    Args:
        context: The AnalysisContext (or any object exposing ``apk_md5`` and
            ``cache_manager``; both are read defensively via ``getattr``).
        module_name: Registered assessment name used as part of the cache key
            (e.g. "deep_dataflow", "pii_flow").
        config: The assessment's config subtree; hashed into the cache key so a
            config change invalidates the cached findings.
        build_fn: Zero-arg callable running the assessment's actual detection
            body (the part that touches androguard / create_xref). Invoked ONLY
            on a cache miss.

    Behavior:
        * Cache HIT  -> reconstruct findings from the stored dicts and return;
          ``build_fn`` is never called, so androguard is never touched.
        * Cache MISS -> call ``build_fn``, persist the findings as dicts, return.
        * No cache manager / no md5 -> just call ``build_fn`` (no caching).

    Never raises: any cache read/write failure degrades to running ``build_fn``.
    """
    md5 = getattr(context, "apk_md5", None)
    cache_manager = getattr(context, "cache_manager", None)

    if not md5 or cache_manager is None:
        return build_fn()

    config_hash = _config_hash(config)

    try:
        cached = cache_manager.get_module_result(md5, module_name, config_hash)
    except Exception as exc:
        logger.debug(f"deep cache read failed for {module_name}/{md5}: {exc}")
        cached = None

    if cached is not None:
        try:
            findings = findings_from_cache(cached)
            logger.debug(
                f"deep cache HIT ({module_name}) for {md5}: "
                f"{len(findings)} findings, androguard xref skipped"
            )
            return findings
        except Exception as exc:
            # A corrupt/incompatible payload must never break the run — recompute.
            logger.debug(f"deep cache payload for {module_name}/{md5} unusable: {exc}")

    findings = build_fn()

    try:
        payload = {"findings": [f.to_dict() for f in findings]}
        cache_manager.set_module_result(md5, module_name, config_hash, payload)
        logger.debug(f"deep cache STORE ({module_name}) for {md5}: {len(findings)} findings")
    except Exception as exc:
        logger.debug(f"deep cache write failed for {module_name}/{md5}: {exc}")

    return findings


def findings_from_cache(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Reconstruct a list of ``SecurityFinding`` from a cached payload dict."""
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        return []
    return [finding_from_dict(d) for d in findings if isinstance(d, dict)]


def finding_from_dict(data: dict[str, Any]) -> SecurityFinding:
    """Rebuild a ``SecurityFinding`` from its ``to_dict()`` representation.

    The round-trip is lossless for every field the report and risk scorer read:
    category, severity (enum), title, description, evidence, recommendations,
    cve_references, additional_data, confidence, verification_status (enum) and
    the optional file location.
    """
    return SecurityFinding(
        category=data.get("category", ""),
        severity=_severity_from_value(data.get("severity")),
        title=data.get("title", ""),
        description=data.get("description", ""),
        evidence=list(data.get("evidence") or []),
        recommendations=list(data.get("recommendations") or []),
        cve_references=list(data.get("cve_references") or []),
        additional_data=dict(data.get("additional_data") or {}),
        file_location=_file_location_from_dict(data.get("fileLocation")),
        confidence=data.get("confidence"),
        verification_status=_verification_status_from_value(data.get("verification_status")),
    )


def _severity_from_value(value: Any) -> AnalysisSeverity:
    """Map a severity value string back to the enum (defaults to LOW)."""
    try:
        return AnalysisSeverity(value)
    except (ValueError, KeyError):
        return AnalysisSeverity.LOW


def _verification_status_from_value(value: Any) -> VerificationStatus:
    """Map a verification-status value string back to the enum.

    Defaults to CONFIRMED to mirror ``SecurityFinding``'s own default so a
    payload missing the field round-trips to the same value.
    """
    try:
        return VerificationStatus(value)
    except (ValueError, KeyError):
        return VerificationStatus.CONFIRMED


def _file_location_from_dict(data: Any) -> FileLocation | None:
    """Rebuild a ``FileLocation`` from its ``to_dict()`` form, or None."""
    if not isinstance(data, dict) or "uri" not in data:
        return None
    return FileLocation(
        uri=data.get("uri"),
        start_line=data.get("startLine"),
        start_offset=data.get("startOffset"),
        end_line=data.get("endLine"),
        end_offset=data.get("endOffset"),
    )
