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

"""
Tracker Database for Pattern-Based Detection.

Signature database of known trackers, network recipients and anti-analysis /
integrity protections. The data lives in ``signature_db.json`` (shipped as
package data) so it can be shared with other tools, e.g. Sandroid uses
:func:`label_for_domain` to label captured network traffic.

Each entry is keyed by a stable ``id`` and has a ``kind``:

- ``tracker``: SDK with code ``patterns`` and network patterns/domains
- ``recipient``: network endpoint only (``network_domains`` + ``label``)
- ``protection``: anti-analysis / integrity SDK (``code_signature`` package
  regex, ``entry_points`` class regexes, ``native_libs``, ``defeats``,
  ``confidence``)

Entries from a user file (config key ``tracker_db_path``) extend the built-in
ones or override them field by field, matched by id.
"""

import copy
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SIGNATURE_DB_PATH = Path(__file__).with_name("signature_db.json")
ENTRY_KINDS = ("tracker", "recipient", "protection")
PROTECTION_DEFEATS = ("root", "frida", "debug", "emulator", "integrity", "ssl")
#: Entry fields that must be lists of strings
LIST_FIELDS = (
    "patterns",
    "version_patterns",
    "network_patterns",
    "network_domains",
    "native_libs",
    "defeats",
    "entry_points",
)
#: Evidence levels of a detected protection
EVIDENCE_LEVELS = ("sdk_present", "entry_point")


@lru_cache(maxsize=1)
def _load_builtin_entries() -> dict[str, dict[str, Any]]:
    with SIGNATURE_DB_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)["entries"]


def load_signature_db(path: str | None = None) -> dict[str, dict[str, Any]]:
    """
    Load the signature database.

    Args:
        path: Optional JSON file with the same layout as the built-in
            ``signature_db.json`` (``{"entries": {id: {...}}}``). Its entries
            are merged onto the built-in ones by id: new ids are added,
            fields of existing ids are overridden, and ``"disabled": true``
            removes an entry. Entries without ``kind`` default to ``tracker``.

    Returns:
        Dict mapping entry id to entry (a fresh copy; safe to modify).

    Raises:
        OSError, ValueError: If ``path`` cannot be read or is malformed.
    """
    entries = copy.deepcopy(_load_builtin_entries())
    if not path:
        return entries

    with Path(path).expanduser().open(encoding="utf-8") as fh:
        data = json.load(fh)
    overrides = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(overrides, dict):
        raise ValueError(f"Signature DB {path} must be a JSON object with an 'entries' object")

    for entry_id, fields in overrides.items():
        if not isinstance(fields, dict):
            raise ValueError(f"Signature DB {path}: entry '{entry_id}' must be an object")
        if fields.get("disabled") is True:
            entries.pop(entry_id, None)
            continue
        for field in LIST_FIELDS:
            value = fields.get(field)
            if value is not None and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
                raise ValueError(f"Signature DB {path}: '{entry_id}.{field}' must be a list of strings")
        merged = {**entries.get(entry_id, {}), **fields, "override": True}
        merged.setdefault("kind", "tracker")
        if merged["kind"] not in ENTRY_KINDS:
            raise ValueError(f"Signature DB {path}: entry '{entry_id}' has unknown kind '{merged['kind']}'")
        entries[entry_id] = merged

    names: dict[str, str] = {}
    for entry_id, entry in entries.items():
        if entry.get("kind") != "tracker":
            continue
        name = entry.get("name", entry_id)
        if name in names:
            logger.warning(
                f"Signature DB {path}: trackers '{names[name]}' and '{entry_id}' share the name '{name}'; "
                f"only '{entry_id}' is used for tracker detection"
            )
        names[name] = entry_id
    logger.debug(f"Loaded {len(overrides)} signature entries from {path}")
    return entries


def _build_domain_index(entries: dict[str, dict[str, Any]]) -> list[tuple[str, bool, str, str]]:
    """Return (suffix, subdomains_only, label, entry_id), most specific first.

    Specificity is the number of labels, then the length; on a tie a domain
    from the user override file (``tracker_db_path``) beats a built-in one.
    ``*.x.com`` matches subdomains of ``x.com`` only.
    """
    ranked = []
    for entry_id, entry in entries.items():
        label = entry.get("label") or entry.get("name") or entry_id
        for domain in entry.get("network_domains") or []:
            suffix = domain.strip().lower().strip(".")
            subdomains_only = suffix.startswith("*.")
            suffix = suffix.removeprefix("*.")
            if suffix:
                rank = (-suffix.count("."), -len(suffix), not entry.get("override"))
                ranked.append((rank, (suffix, subdomains_only, label, entry_id)))
    ranked.sort(key=lambda item: item[0])
    return [item for _, item in ranked]


@lru_cache(maxsize=1)
def _builtin_domain_index() -> tuple[tuple[str, bool, str, str], ...]:
    return tuple(_build_domain_index(_load_builtin_entries()))


def _normalize_host(host: str) -> str:
    """Lower-case a host and strip brackets, a port and the trailing dot."""
    host = host.strip().lower()
    if host.startswith("["):  # [IPv6]:port
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:  # host:port (a bare IPv6 address has several colons)
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def label_for_domain(host: str, entries: dict[str, dict[str, Any]] | None = None) -> tuple[str, str] | None:
    """
    Label a network host using the entries' ``network_domains`` suffixes.

    The most specific matching suffix wins, so ``firebaselogging.googleapis.com``
    resolves to Google Analytics rather than the generic ``googleapis.com``.
    A suffix matches the host itself or any subdomain of it (``evilgoogle.com``
    does not match ``google.com``); a ``*.x.com`` suffix matches subdomains only.

    Args:
        host: Hostname (a port, brackets and the trailing dot are ignored).
        entries: Optional database from :func:`load_signature_db`; defaults
            to the built-in database.

    Returns:
        ``(label, entry_id)`` or ``None`` if no entry matches.
    """
    if not host:
        return None
    host = _normalize_host(host)
    index = _builtin_domain_index() if entries is None else _build_domain_index(entries)
    for suffix, subdomains_only, label, entry_id in index:
        if host.endswith("." + suffix) or (host == suffix and not subdomains_only):
            return label, entry_id
    return None


def _trackers_by_name(entries: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map tracker name -> entry (with its ``id``), the legacy TRACKER_DATABASE shape."""
    return {
        entry.get("name", entry_id): {"id": entry_id, **entry}
        for entry_id, entry in entries.items()
        if entry.get("kind") == "tracker"
    }


class TrackerDatabase:
    """
    Database of known tracker patterns for detection.

    Single Responsibility: Provide access to tracker pattern definitions
    with metadata for advertising, analytics, and tracking SDKs.

    The class-level API (``TRACKER_DATABASE`` and the classmethods) reflects
    the built-in trackers, including entries added to, replaced in or removed
    from ``TRACKER_DATABASE`` at runtime. An instance additionally applies the
    optional user file passed as ``db_path`` (see :func:`load_signature_db`);
    its :meth:`get_trackers` honours runtime changes to ``TRACKER_DATABASE``
    for names the user file does not override.
    """

    # Built-in trackers keyed by name: patterns, version patterns and metadata
    TRACKER_DATABASE: dict[str, dict[str, Any]] = copy.deepcopy(_trackers_by_name(_load_builtin_entries()))

    def __init__(self, db_path: str | None = None):
        """Initialize with the built-in database plus optional overrides from ``db_path``."""
        self.entries = load_signature_db(db_path)

    def get_trackers(self) -> dict[str, dict[str, Any]]:
        """Get the trackers of this instance's database, keyed by name."""
        trackers = _trackers_by_name(self.entries)
        builtin = _trackers_by_name(_load_builtin_entries())
        overridden = {name for name, info in trackers.items() if info.get("override")}
        legacy = type(self).TRACKER_DATABASE
        # Legacy extension point: code that edits TrackerDatabase.TRACKER_DATABASE
        for name in builtin.keys() - legacy.keys() - overridden:
            trackers.pop(name, None)
        for name, info in legacy.items():
            if name not in overridden and info != builtin.get(name):
                trackers[name] = info
        return trackers

    def get_protections(self) -> dict[str, dict[str, Any]]:
        """Get the protection entries of this instance's database, keyed by id."""
        return {entry_id: entry for entry_id, entry in self.entries.items() if entry.get("kind") == "protection"}

    @classmethod
    def get_tracker_database(cls) -> dict[str, dict[str, Any]]:
        """
        Get the complete tracker database.

        Returns:
            Dict mapping tracker names to their pattern definitions
        """
        return cls.TRACKER_DATABASE.copy()

    @classmethod
    def get_tracker_count(cls) -> int:
        """
        Get the total number of tracked patterns.

        Returns:
            Number of tracker patterns in the database
        """
        return len(cls.TRACKER_DATABASE)

    @classmethod
    def get_tracker_categories(cls) -> set:
        """
        Get all unique tracker categories.

        Returns:
            Set of unique category names
        """
        categories = set()
        for tracker_data in cls.TRACKER_DATABASE.values():
            categories.add(tracker_data.get("category", "Unknown"))
        return categories

    @classmethod
    def get_trackers_by_category(cls, category: str) -> dict[str, dict[str, Any]]:
        """
        Get all trackers belonging to a specific category.

        Args:
            category: Category name to filter by

        Returns:
            Dict of trackers in the specified category
        """
        return {name: data for name, data in cls.TRACKER_DATABASE.items() if data.get("category", "") == category}
