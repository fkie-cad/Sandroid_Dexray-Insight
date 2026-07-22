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

"""Authoritative manifest fact resolution for security assessments.

Security assessments need a handful of manifest-level facts (SDK levels, network
security config presence, backup/debuggable flags) to decide whether to emit
findings. The rich, reliable values live in the ``apk_overview`` result
(``general_info`` for SDK ints, ``manifest_security`` for the structured
application-level flags). A thin ``manifest_analysis`` result is used only as a
fallback.

CRITICAL: when a fact is genuinely unavailable (apk_overview failed, split APK,
unparsable manifest) this module returns a ``None`` sentinel rather than a
misleading default such as ``0`` or ``True``. Callers MUST skip the associated
finding when the fact is unknown, otherwise stale defaults resurface as false
positives (e.g. "Target SDK 0", "Backup is enabled").
"""

from typing import Any


def _coerce_int(value: Any) -> int | None:
    """Coerce a value to int, returning None when it is absent/uncoercible."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_dict(obj: Any) -> dict[str, Any] | None:
    """Return a plain-dict view of a ``BaseResult`` or dict, else None.

    Accepts either a dataclass result exposing ``to_dict()`` or a raw dict so
    callers can pass whatever the analysis pipeline produced.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:
            return None
    return None


def _default_facts() -> dict[str, Any]:
    """Return the fact dictionary with all values as unknown sentinels."""
    return {
        "target_sdk": None,
        "min_sdk": None,
        "max_sdk": None,
        # Value of android:networkSecurityConfig (or None when the attribute is
        # absent). Only meaningful together with ``network_security_config_known``.
        "network_security_config": None,
        # True only when the manifest was successfully inspected so that the
        # absence of a network security config is a *known* absence rather than
        # simply unavailable data.
        "network_security_config_known": False,
        # True/False when known; None when unknown.
        "allow_backup": None,
        "uses_cleartext_traffic": None,
        "debuggable": None,
    }


def _merge_from_apk_overview(facts: dict[str, Any], apk_overview: dict[str, Any]) -> None:
    """Merge authoritative facts from the apk_overview result (preferred source)."""
    general_info = apk_overview.get("general_info") or {}
    facts["target_sdk"] = _coerce_int(general_info.get("target_sdk"))
    facts["min_sdk"] = _coerce_int(general_info.get("min_sdk"))
    facts["max_sdk"] = _coerce_int(general_info.get("max_sdk"))

    manifest_security = apk_overview.get("manifest_security")
    if isinstance(manifest_security, dict) and manifest_security:
        # A populated manifest_security means the manifest was inspected, so the
        # presence/absence of the network security config is a known fact.
        facts["network_security_config"] = manifest_security.get("network_security_config")
        facts["network_security_config_known"] = True
        facts["allow_backup"] = manifest_security.get("allow_backup")
        facts["uses_cleartext_traffic"] = manifest_security.get("uses_cleartext_traffic")
        facts["debuggable"] = manifest_security.get("debuggable")


def _merge_from_thin_manifest(facts: dict[str, Any], manifest_data: dict[str, Any] | None) -> None:
    """Merge facts from the thin manifest_analysis result (fallback source)."""
    if not manifest_data:
        return

    facts["target_sdk"] = _coerce_int(manifest_data.get("target_sdk_version"))
    facts["min_sdk"] = _coerce_int(manifest_data.get("min_sdk_version"))
    facts["max_sdk"] = _coerce_int(manifest_data.get("max_sdk_version"))

    nsc = manifest_data.get("network_security_config")
    if nsc:
        # Only a positive value is trustworthy here; the thin dict cannot
        # reliably signal a *known* absence, so leave it unknown otherwise.
        facts["network_security_config"] = nsc
        facts["network_security_config_known"] = True

    debug_flags = manifest_data.get("debug_flags")
    if isinstance(debug_flags, dict):
        if "allow_backup" in debug_flags:
            facts["allow_backup"] = debug_flags.get("allow_backup")
        if "debuggable" in debug_flags:
            facts["debuggable"] = debug_flags.get("debuggable")

    cleartext = manifest_data.get("uses_cleartext_traffic")
    if cleartext is not None:
        facts["uses_cleartext_traffic"] = cleartext


def get_manifest_facts(analysis_results: Any) -> dict[str, Any]:
    """Resolve authoritative manifest facts for security assessments.

    Merges ``apk_overview.general_info`` (SDK ints) with
    ``apk_overview.manifest_security`` (structured flags). Falls back to the thin
    ``manifest_analysis`` result only when apk_overview is absent.

    Args:
        analysis_results: The combined analysis results (a dict of module name to
            result, or an object exposing ``to_dict()``).

    Returns:
        A dict with keys ``target_sdk``, ``min_sdk``, ``max_sdk``,
        ``network_security_config``, ``network_security_config_known``,
        ``allow_backup``, ``uses_cleartext_traffic`` and ``debuggable``. Every
        value is a ``None``/False unknown sentinel when the fact is unavailable;
        callers MUST skip findings for unknown facts.
    """
    facts = _default_facts()

    results = _extract_dict(analysis_results)
    if results is None:
        return facts

    apk_overview = _extract_dict(results.get("apk_overview"))
    if apk_overview is not None:
        _merge_from_apk_overview(facts, apk_overview)
    else:
        _merge_from_thin_manifest(facts, _extract_dict(results.get("manifest_analysis")))

    return facts
