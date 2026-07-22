#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

"""
Public Suffix List (PSL) support for offline domain validation.

Implements a small, dependency-free Public Suffix List matcher following the
algorithm described at https://publicsuffix.org/list/. It is used as the
authoritative gate that separates genuine registrable domains (``kik.com``,
``example.co.uk``) from code identifiers that merely *look* like domains
(``ad.instance.ready``, ``shouldSkipUpdateUi.false``).

Design notes:
- The list is bundled with the package (``resources/public_suffix_list.dat``)
  and loaded exactly once via ``functools.lru_cache``. The runtime NEVER
  fetches the list from the network -- it only reads the bundled file.
- ``registrable_domain`` is intentionally *strict*: unlike the reference PSL
  algorithm it does NOT fall back to the implicit ``*`` rule for unknown
  top-level labels. An unknown TLD (e.g. ``.ready``, ``.false``, ``.values``)
  therefore yields no registrable domain, which is exactly the behaviour we
  want for false-positive filtering.
"""

import functools
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Bundled list lives next to this module under ../resources/
_PSL_PATH = Path(__file__).resolve().parent.parent / "resources" / "public_suffix_list.dat"

# Minimal curated fallback used only if the bundled file is missing/unreadable.
# This keeps domain validation functional in degraded installs. It is NOT a
# substitute for the full bundled list -- maintainers should run
# `python scripts/update_psl.py` (or `make update-psl`) to refresh the real one.
_FALLBACK_RULES = [
    "com",
    "org",
    "net",
    "io",
    "co",
    "info",
    "biz",
    "gov",
    "edu",
    "mil",
    "int",
    "dev",
    "app",
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "com.br",
    "co.in",
    "github.io",
    "herokuapp.com",
]


class PublicSuffixList:
    """
    Pure-Python Public Suffix List matcher.

    Single Responsibility: given a domain, determine its public suffix and
    registrable domain using PSL exact/wildcard/exception rules.
    """

    def __init__(self, rule_lines, is_fallback: bool = False):
        """
        Build the matcher from an iterable of raw PSL rule lines.

        Args:
            rule_lines: Iterable of raw lines from a public_suffix_list.dat file.
            is_fallback: True if built from the curated fallback rather than
                the full bundled list (used for diagnostics only).
        """
        self.is_fallback = is_fallback
        self._exact_rules: set[str] = set()
        self._wildcard_parents: set[str] = set()
        self._exceptions: set[str] = set()

        for raw in rule_lines:
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            # Rules never contain whitespace; guard against trailing comments.
            rule = line.split()[0].lower()
            if rule.startswith("!"):
                self._exceptions.add(rule[1:])
            elif rule.startswith("*."):
                self._wildcard_parents.add(rule[2:])
            else:
                self._exact_rules.add(rule)

    def _public_suffix_length(self, labels: list[str]) -> int:
        """
        Return the number of trailing labels that form the public suffix.

        Returns 0 when no PSL rule matches (strict mode -- no implicit ``*``
        fallback), meaning the domain has no recognised public suffix.
        """
        n = len(labels)

        # Exception rules win over everything else. An exception makes the
        # public suffix one label shorter than the matched rule.
        for i in range(n):
            if ".".join(labels[i:]) in self._exceptions:
                return n - i - 1

        best = 0
        for i in range(n):
            suffix = ".".join(labels[i:])
            length = n - i
            if suffix in self._exact_rules and length > best:
                best = length
            # Wildcard rule "*.parent" matches "<label>.parent". For the
            # candidate suffix starting at index i, the wildcard parent is the
            # remainder labels[i+1:].
            parent = ".".join(labels[i + 1:])
            if parent and parent in self._wildcard_parents and length > best:
                best = length
        return best

    def is_public_suffix(self, labels: list[str]) -> bool:
        """
        Return True if the given labels are exactly a public suffix.

        Args:
            labels: Domain labels, e.g. ["co", "uk"].
        """
        if not labels:
            return False
        return self._public_suffix_length(labels) == len(labels)

    def registrable_domain(self, domain: str) -> str | None:
        """
        Return the registrable domain (public suffix + 1 label) or None.

        Examples:
            "smiley-cdn.kik.com" -> "kik.com"
            "example.co.uk"      -> "example.co.uk"
            "ad.instance.ready"  -> None   (".ready" is not a public suffix)

        Args:
            domain: A domain name (case-insensitive, trailing dot tolerated).

        Returns:
            The registrable domain, or None if the domain has no recognised
            public suffix or is itself only a public suffix.
        """
        if not domain:
            return None
        normalized = domain.strip().strip(".").lower()
        if not normalized or "." not in normalized:
            return None

        labels = normalized.split(".")
        suffix_len = self._public_suffix_length(labels)
        if suffix_len == 0:
            return None
        # A registrable domain needs at least one label in front of the suffix.
        if len(labels) <= suffix_len:
            return None
        return ".".join(labels[len(labels) - suffix_len - 1:])


def _load_rule_lines() -> tuple[list[str], bool]:
    """
    Load raw PSL lines from the bundled file, or the curated fallback.

    Returns:
        Tuple of (rule_lines, is_fallback).
    """
    try:
        with _PSL_PATH.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
        if lines:
            return lines, False
        logger.warning("Bundled public suffix list at %s is empty; using curated fallback", _PSL_PATH)
    except OSError as exc:
        logger.warning(
            "Could not read bundled public suffix list at %s (%s); using curated fallback",
            _PSL_PATH,
            exc,
        )
    return list(_FALLBACK_RULES), True


@functools.lru_cache(maxsize=1)
def get_public_suffix_list() -> PublicSuffixList:
    """
    Return the process-wide singleton PublicSuffixList.

    Loads the bundled list once (never from the network). Falls back to a
    small curated rule set only if the bundled file cannot be read.
    """
    rule_lines, is_fallback = _load_rule_lines()
    psl = PublicSuffixList(rule_lines, is_fallback=is_fallback)
    if is_fallback:
        logger.warning(
            "PublicSuffixList initialised from curated FALLBACK rules (%d rules). "
            "Run 'python scripts/update_psl.py' to restore the full bundled list.",
            len(psl._exact_rules),
        )
    else:
        logger.debug(
            "PublicSuffixList loaded from bundled list: %d exact, %d wildcard, %d exception rules",
            len(psl._exact_rules),
            len(psl._wildcard_parents),
            len(psl._exceptions),
        )
    return psl
