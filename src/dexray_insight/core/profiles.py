#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Named analysis profiles: ready-made configuration overrides for common goals.

A profile is a partial configuration merged on top of the defaults and ``dexray.yaml``
but *below* everything the user states explicitly: keys of a ``-c`` config file
whose value differs from the built-in defaults (so a full copy of the shipped
``dexray.yaml`` does not cancel the profile), every key of a ``config_dict`` and every
CLI flag. A file that enables a module the defaults leave off keeps it enabled::

    Configuration(profile="privacy")
    Configuration(profile="privacy", config_dict={"modules": {"tracker_analysis": {"enabled": False}}})

Profiles:

* ``generic`` -- the regular full analysis; no overrides.
* ``privacy`` -- what an app collects and shares: manifest, permissions (with
  API invocation), strings (URLs, domains, e-mail addresses), trackers, behaviour
  (fast mode) and library detection without the expensive similarity engine. Native
  binary analysis, signature lookups, .NET analysis, APK diffing, apktool/JADX
  decompilation and the APK unpacking they need are switched off. When the caller
  enables the security assessment, only the privacy-relevant assessments run
  (PII, PII flows, sensitive data, provider paths, ad-SDK surface, access control,
  misconfiguration such as cleartext traffic and backups).

Neither profile turns the security assessment itself on or off; that stays the
caller's choice (``security.enable_owasp_assessment`` / ``-s``).

A profile also lists *requirements*: when the caller or a CLI flag switches on a
feature that needs parts the profile turned off (``--cve`` needs library versions
from apktool, native analysis and the similarity engine), those parts are switched
back on, unless they were set explicitly; then a warning says the feature is limited.
A feature switched on only by a ``-c`` file does not pull its prerequisites back.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass(frozen=True)
class AnalysisProfile:
    """A named configuration override.

    Attributes:
        name: Profile identifier (``"privacy"``).
        title: Short human-readable name.
        description: One sentence on what the profile is for.
        overrides: Partial configuration merged over the defaults.
    """

    name: str
    title: str
    description: str
    overrides: dict[str, Any] = field(default_factory=dict)
    #: ``(feature, switch_path, {trigger_path: value}, {path: value})``: when the
    #: configuration has every trigger value and ``switch_path`` was set by the
    #: caller (``config_dict``) or a CLI flag (not by a ``-c`` file), every
    #: ``path`` that was not set explicitly is set to ``value``.
    requirements: tuple[tuple[str, tuple[str, ...], dict[tuple[str, ...], Any], dict[tuple[str, ...], Any]], ...] = ()


_OFF = {"enabled": False}

_PRIVACY_OVERRIDES: dict[str, Any] = {
    "modules": {
        "apk_overview": {"enabled": True},
        "manifest_analysis": {"enabled": True},
        "permission_analysis": {"enabled": True},
        "api_invocation": {"enabled": True},
        "privacy_analysis": {"enabled": True},
        "string_analysis": {"enabled": True},
        "tracker_analysis": {"enabled": True},
        "behaviour_analysis": {"enabled": True, "deep_mode": False},
        "library_detection": {
            "enabled": True,
            "enable_similarity": False,
            "version_analysis": {"enabled": False},
        },
        "native_analysis": dict(_OFF),
        "signature_detection": dict(_OFF),
        "dotnet_analysis": dict(_OFF),
        "apk_diffing": dict(_OFF),
    },
    "tools": {
        "apktool": dict(_OFF),
        "jadx": dict(_OFF),
        "kavanoz": dict(_OFF),
    },
    # Nothing left that needs the unpacked APK or a decompiled tree.
    "temporal_analysis": dict(_OFF),
    "security": {
        "cve_scanning": dict(_OFF),
        "assessments": {
            "injection": dict(_OFF),
            "authentication_failures": dict(_OFF),
            "logging_monitoring_failures": dict(_OFF),
            "vulnerable_components": dict(_OFF),
            "cve_scanning": dict(_OFF),
            "ssrf": dict(_OFF),
            "integrity_failures": dict(_OFF),
            "insecure_design": dict(_OFF),
        },
    },
}

_PRIVACY_REQUIREMENTS = (
    # CVE scanning (security on plus --cve / security.cve_scanning.enabled)
    # needs versioned libraries.
    (
        "CVE scanning",
        ("security", "cve_scanning", "enabled"),
        {("security", "enable_owasp_assessment"): True, ("security", "cve_scanning", "enabled"): True},
        {
            ("modules", "native_analysis", "enabled"): True,
            ("modules", "library_detection", "enable_similarity"): True,
            ("modules", "library_detection", "version_analysis", "enabled"): True,
            ("tools", "apktool", "enabled"): True,
            ("temporal_analysis", "enabled"): True,
            ("security", "assessments", "vulnerable_components", "enabled"): True,
            ("security", "assessments", "cve_scanning", "enabled"): True,
        },
    ),
)

ANALYSIS_PROFILES: dict[str, AnalysisProfile] = {
    "generic": AnalysisProfile(
        name="generic",
        title="Generic",
        description="Full analysis with every module enabled in the configuration.",
        overrides={},
    ),
    "privacy": AnalysisProfile(
        name="privacy",
        title="Privacy",
        description=(
            "Permissions, trackers, privacy-relevant APIs, strings and behaviour; "
            "skips native, decompilation and unrelated security checks."
        ),
        overrides=_PRIVACY_OVERRIDES,
        requirements=_PRIVACY_REQUIREMENTS,
    ),
}

#: Profile used when none is named.
DEFAULT_PROFILE = "generic"


def list_profiles() -> dict[str, str]:
    """Return ``{name: description}`` for every available profile."""
    return {name: profile.description for name, profile in ANALYSIS_PROFILES.items()}


def get_profile(name: str) -> AnalysisProfile:
    """Return the profile called ``name`` (case-insensitive).

    Raises:
        ValueError: For an unknown profile name.
    """
    key = (name or "").strip().lower()
    if key not in ANALYSIS_PROFILES:
        known = ", ".join(sorted(ANALYSIS_PROFILES))
        raise ValueError(f"Unknown analysis profile {name!r} (known: {known})")
    return ANALYSIS_PROFILES[key]


def get_profile_overrides(name: str) -> dict[str, Any]:
    """Return a deep copy of the configuration overrides of profile ``name``."""
    return copy.deepcopy(get_profile(name).overrides)


__all__ = [
    "ANALYSIS_PROFILES",
    "DEFAULT_PROFILE",
    "AnalysisProfile",
    "get_profile",
    "get_profile_overrides",
    "list_profiles",
]
