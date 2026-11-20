#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Permissions an APK requests in its manifest.

Androguard's ``APK.get_permissions()`` (and Insight's ``APK_Overview`` fork of it)
only reads ``<uses-permission>``. A permission requested with
``<uses-permission-sdk-23>`` (granted on API 23+ only) is silently missing, and the
``maxSdkVersion`` of a request is not part of the name list, so consumers cannot
tell which requests a given Android release actually applies.

The helpers here read both tags from any androguard-compatible APK object (one that
provides ``find_tags`` and ``get_value_from_tag``) and keep each request's tag and
``maxSdkVersion``:

* :func:`requested_permission_entries` -- one entry per manifest request, in manifest
  order (``{"name", "tag", "max_sdk_version"}``).
* :func:`requested_permission_names` -- the unique names (both tags), in manifest
  order. This is what Insight reports as ``permissions``.
* :func:`effective_permission_names` -- the names a device running a given API level
  keeps: a request whose ``maxSdkVersion`` is below that level is dropped by the
  package manager. This is what ``dumpsys package`` lists as "requested permissions"
  (before any permissions the platform adds implicitly).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: Manifest tags that request a permission.
USES_PERMISSION_TAGS = ("uses-permission", "uses-permission-sdk-23")


def _max_sdk(apk: Any, tag: Any) -> int | None:
    """``android:maxSdkVersion`` of a request tag as int, ``None`` when absent/invalid."""
    try:
        value = apk.get_value_from_tag(tag, "maxSdkVersion")
    except Exception:
        return None
    if value is None or value == "":
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        logger.debug(f"Ignoring invalid maxSdkVersion {value!r} on a permission request")
        return None
    # The package manager treats 0 (and anything below 1) as "no limit".
    return number if number > 0 else None


def _parser_permission_names(apk: Any) -> list[str]:
    """``apk.get_permissions()`` as a list of strings (``[]`` on any failure)."""
    try:
        names = apk.get_permissions() or []
        return [str(name) for name in names if name]
    except Exception:
        return []


def requested_permission_entries(apk: Any) -> list[dict[str, Any]]:
    """Every permission request in the manifest, in manifest order.

    Args:
        apk: An androguard ``APK`` or Insight ``APK_Overview`` object.

    Returns:
        ``[{"name": str, "tag": "uses-permission" | "uses-permission-sdk-23",
        "max_sdk_version": int | None}, ...]``. A name requested twice yields two
        entries. Names that ``apk.get_permissions()`` knows but the tag scan did not
        find (or an object without ``find_tags``) are appended as ``uses-permission``
        entries without a maxSdkVersion, so nothing the parser reports is lost.
    """
    if apk is None:
        return []

    entries: list[dict[str, Any]] = []
    if hasattr(apk, "find_tags") and hasattr(apk, "get_value_from_tag"):
        for tag_name in USES_PERMISSION_TAGS:
            try:
                tags = list(apk.find_tags(tag_name))
            except Exception as e:
                logger.debug(f"Could not read <{tag_name}> tags: {e}")
                continue
            for tag in tags:
                try:
                    name = apk.get_value_from_tag(tag, "name")
                except Exception:
                    name = None
                if not isinstance(name, str) or not name:
                    continue
                entries.append({"name": name, "tag": tag_name, "max_sdk_version": _max_sdk(apk, tag)})

    seen = {entry["name"] for entry in entries}
    for name in _parser_permission_names(apk):
        if name not in seen:
            seen.add(name)
            entries.append({"name": name, "tag": "uses-permission", "max_sdk_version": None})
    return entries


def _unique(names: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for name in names:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def requested_permission_names(apk: Any) -> list[str]:
    """Unique permission names requested with either tag, in manifest order."""
    return _unique([entry["name"] for entry in requested_permission_entries(apk)])


def effective_permission_names(entries: list[dict[str, Any]], api_level: int) -> list[str]:
    """Unique names a device on ``api_level`` keeps from the given request entries.

    A request with ``maxSdkVersion`` below ``api_level`` is ignored by the package
    manager, and ``<uses-permission-sdk-23>`` only applies from API 23 on; a
    ``maxSdkVersion`` of 0 or less means no limit. Permissions the platform adds on
    its own (split permissions for old target SDKs) are not part of the manifest and
    therefore not included.

    Args:
        entries: Output of :func:`requested_permission_entries` (or the
            ``requested_permissions`` list of an Insight result).
        api_level: The device's API level.

    Returns:
        The unique names, in manifest order.
    """
    kept = []
    for entry in entries or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        if entry.get("tag") == "uses-permission-sdk-23" and api_level < 23:
            continue
        max_sdk = entry.get("max_sdk_version")
        if isinstance(max_sdk, int) and 0 < max_sdk < api_level:
            continue
        kept.append(str(entry["name"]))
    return _unique(kept)


__all__ = [
    "USES_PERMISSION_TAGS",
    "effective_permission_names",
    "requested_permission_entries",
    "requested_permission_names",
]
