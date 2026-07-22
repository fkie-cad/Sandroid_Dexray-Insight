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

"""Shared weak-cryptography evidence collection.

Consolidates the "is this a weak algorithm reference?" logic used by the
sensitive-data, insecure-design and mobile-specific assessments so that all
three apply the same evidence rules:

* an algorithm token counts only as a ``Cipher/MessageDigest.getInstance``
  argument, or as a *whole word* (``\\bDES\\b``) - never a substring; and
* JVM type descriptors / placeholders are dropped first.

This removes the historical false positives where the substring ``des`` matched
``Descriptor`` / ``desktop`` / ``adDescriptor.bids``.
"""

from typing import Any

from .descriptors import is_probably_placeholder
from .descriptors import looks_like_type_descriptor
from .sinks import extract_algorithm_argument
from .whole_word import find_weak_crypto_tokens


def collect_weak_crypto_evidence(analysis_results: dict[str, Any], all_strings: list) -> list[str]:
    """Return evidence strings for weak-crypto usage using whole-word/arg rules.

    Args:
        analysis_results: combined analysis results (for ``api_invocation``).
        all_strings: decompiled strings to scan (already extracted by caller).
    """
    evidence: list[str] = []

    # 1) Structured crypto_usage entries (algorithm already parsed upstream).
    api_results = analysis_results.get("api_invocation", {}) if isinstance(analysis_results, dict) else {}
    api_data = api_results.to_dict() if hasattr(api_results, "to_dict") else api_results
    if isinstance(api_data, dict):
        crypto_usage = api_data.get("crypto_usage", [])
        if isinstance(crypto_usage, (list, tuple)):
            for entry in crypto_usage:
                if isinstance(entry, dict):
                    algorithm = str(entry.get("algorithm", ""))
                    if find_weak_crypto_tokens(algorithm):
                        location = entry.get("location", "unknown")
                        evidence.append(f"Weak algorithm {algorithm} at {location}")

    # 2) Decompiled strings: a weak token inside a getInstance() argument, or a
    #    whole-word token in a non-descriptor / non-placeholder string.
    if isinstance(all_strings, (list, tuple)):
        for string in all_strings:
            if not isinstance(string, str):
                continue
            if looks_like_type_descriptor(string) or is_probably_placeholder(string):
                continue

            argument = extract_algorithm_argument(string)
            if argument and find_weak_crypto_tokens(argument):
                evidence.append(f"Weak algorithm in getInstance: {string[:70]}")
                continue

            tokens = find_weak_crypto_tokens(string)
            if tokens:
                evidence.append(f"Weak algorithm reference ({', '.join(tokens)}): {string[:70]}")

    return evidence
