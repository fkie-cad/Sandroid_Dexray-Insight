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

"""Package-name classification for exported-component triage.

Real apps declare dozens of exported components that belong to the Android
framework, AndroidX, Google Play services / Firebase, and common ad / analytics
SDKs. On Kik's ``base.apk`` roughly 14 of 20 "potentially exported" findings were
these third-party receivers (Firebase, WorkManager, AdMob, ...). They are
declared exported by the SDK author, not by the app, and flood the report with
low-value noise.

This module classifies a component name into ``first_party`` / ``framework`` /
``unknown`` so callers can *down-rank* framework-owned components. The allowlist
is a DOWN-RANK, never a delete: framework findings are still emitted, only at a
reduced severity/confidence.

Spoof resistance is the critical invariant. A repackaged/trojanized app can
rename a malicious component ``com.google.firebase.MessagingService`` to hide it.
Therefore the caller must NEVER allow package name alone to suppress a component
that is reachable from the outside world via a ``BROWSABLE`` intent filter or a
custom URI scheme - those are deep-link entry points and are always surfaced
regardless of the package name. :func:`classify_component` only reports the
name-based classification; the BROWSABLE / custom-scheme override lives in the
caller (see :func:`carries_browsable_or_custom_scheme`).
"""

from typing import Any

# Package prefixes owned by the Android platform, AndroidX, Google, common
# language runtimes and widely-used third-party SDKs (networking, DI, ads,
# mediation). Components under these prefixes are declared exported by the SDK
# vendor, not by the app author, so they are down-ranked (never dropped).
FRAMEWORK_PREFIXES: tuple[str, ...] = (
    "android.",
    "androidx.",
    "com.android.",
    "com.google.android.gms.",
    "com.google.firebase.",
    "com.google.android.",
    "com.google.",
    "kotlin.",
    "kotlinx.",
    "com.facebook.",
    "com.squareup.",
    "io.reactivex.",
    "dagger.",
    # Ad networks / mediation SDKs frequently ship exported receivers.
    "com.applovin.",
    "com.mopub.",
    "com.unity3d.",
    "com.mbridge.",
    "com.ironsource.",
    "com.vungle.",
    "com.adcolony.",
    "com.chartboost.",
    "com.ogury.",
    "io.wondrous.",
    "com.inmobi.",
    "com.fyber.",
    "com.tapjoy.",
    "com.smaato.",
    "com.bytedance.",
    "com.pangle.",
    "androidx.work.",
    "com.onesignal.",
    "com.appsflyer.",
    "com.adjust.",
    "io.branch.",
)


def classify_component(
    name: str,
    package_name: str | None = None,
    first_party_prefixes: list[str] | tuple[str, ...] | None = None,
    library_results: Any = None,
) -> str:
    """Classify a component name into ``first_party`` / ``framework`` / ``unknown``.

    Rules (applied in order):

    1. ``first_party`` if ``name`` starts with the app ``package_name`` or with a
       configured ``first_party_prefix``. First-party wins over framework so an
       app that (unusually) namespaces itself under a framework-looking prefix is
       still treated as its own code.
    2. ``framework`` if ``name`` starts with a :data:`FRAMEWORK_PREFIXES` entry,
       or is corroborated by a matching library fingerprint in ``library_results``.
    3. ``unknown`` otherwise.

    This is name-based only. It intentionally does NOT know about intent filters;
    the BROWSABLE / custom-scheme spoof-resistance override belongs to the caller
    so it applies uniformly no matter what the package name looks like.
    """
    if not isinstance(name, str) or not name:
        return "unknown"

    # 1. First-party wins.
    if package_name and name.startswith(package_name):
        return "first_party"
    if first_party_prefixes:
        for prefix in first_party_prefixes:
            if prefix and name.startswith(prefix):
                return "first_party"

    # 2. Framework by static prefix list.
    for prefix in FRAMEWORK_PREFIXES:
        if name.startswith(prefix):
            return "framework"

    # 2b. Framework corroborated by a detected-library fingerprint (a stronger
    # signal than the static list). Only treat as framework if the component name
    # sits under a package that a library detector actually matched.
    if _matches_library_fingerprint(name, library_results):
        return "framework"

    # 3. Everything else is unknown (surfaced, not down-ranked).
    return "unknown"


def should_downrank(classification: str) -> bool:
    """Return True when a classification should be down-ranked (never dropped).

    Only ``framework`` components are down-ranked. ``first_party`` and
    ``unknown`` components are surfaced at their normal severity/confidence.
    """
    return classification == "framework"


def carries_browsable_or_custom_scheme(intent_filters: Any) -> bool:
    """Return True if any intent filter is a deep-link / browser entry point.

    A component with a ``BROWSABLE`` category or a custom ``data`` URI scheme is
    an externally reachable entry point. Repackaging can spoof a
    ``com.google.*`` name onto such a component, so these are ALWAYS surfaced
    regardless of package-name classification.

    Handles the manifest shape produced by manifest_analysis where each entry is
    ``{"component_type", "component_name", "filters": {...}}`` and ``filters`` is
    the androguard dict (``{"action": [...], "category": [...], "data"/"scheme":
    ...}``). Also tolerates a flat legacy shape.
    """
    if not intent_filters:
        return False
    if isinstance(intent_filters, dict):
        intent_filters = [intent_filters]
    if not isinstance(intent_filters, (list, tuple)):
        return False

    for entry in intent_filters:
        filters = entry.get("filters", entry) if isinstance(entry, dict) else entry
        if not isinstance(filters, dict):
            continue

        # BROWSABLE category anywhere.
        categories = filters.get("category", filters.get("categories", [])) or []
        if isinstance(categories, (list, tuple)):
            if any("BROWSABLE" in str(c).upper() for c in categories):
                return True
        elif "BROWSABLE" in str(categories).upper():
            return True

        # Custom URI scheme via data / scheme keys.
        if _has_custom_scheme(filters):
            return True

    return False


# Well-known, non-custom schemes that do not by themselves make a component an
# interesting external entry point (http/https deep links are still surfaced via
# BROWSABLE which usually accompanies them).
_STANDARD_SCHEMES = frozenset({"http", "https", "content", "file", "tel", "mailto", "sms", "smsto", "geo", "market"})


def _has_custom_scheme(filters: dict[str, Any]) -> bool:
    """Detect a custom (non-standard) URI scheme in an intent-filter ``data`` block."""
    candidates: list[str] = []

    data = filters.get("data")
    if isinstance(data, dict):
        scheme = data.get("scheme")
        if scheme:
            candidates.append(str(scheme))
    elif isinstance(data, (list, tuple)):
        for item in data:
            if isinstance(item, dict) and item.get("scheme"):
                candidates.append(str(item["scheme"]))
            elif isinstance(item, str):
                candidates.append(item)

    scheme = filters.get("scheme")
    if isinstance(scheme, str) and scheme:
        candidates.append(scheme)
    elif isinstance(scheme, (list, tuple)):
        candidates.extend(str(s) for s in scheme if s)

    for raw in candidates:
        token = raw.strip().rstrip(":/").lower()
        if token and token not in _STANDARD_SCHEMES:
            return True
    return False


def _matches_library_fingerprint(name: str, library_results: Any) -> bool:
    """Return True if ``name`` sits under a package a library detector matched.

    ``library_results`` is read defensively: it may be a list of dicts / objects
    with a ``package``/``package_name`` attribute, a dict, or absent. Any shape we
    do not understand yields False (fall back to the static prefix list only).
    """
    if not library_results:
        return False

    packages: list[str] = []
    try:
        iterable = library_results
        if isinstance(library_results, dict):
            iterable = (
                library_results.get("detected_libraries")
                or library_results.get("libraries")
                or list(library_results.values())
            )
        if not isinstance(iterable, (list, tuple)):
            return False
        for lib in iterable:
            pkg = None
            if isinstance(lib, dict):
                pkg = lib.get("package") or lib.get("package_name") or lib.get("root_package")
            else:
                pkg = getattr(lib, "package", None) or getattr(lib, "package_name", None)
            if pkg:
                packages.append(str(pkg))
    except (TypeError, AttributeError):
        return False

    return any(pkg and name.startswith(pkg) for pkg in packages)
