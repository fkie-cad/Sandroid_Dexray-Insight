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

import re
from typing import Any

from .descriptors import is_probably_placeholder
from .descriptors import looks_like_type_descriptor
from .package_allowlist import FRAMEWORK_PREFIXES
from .sinks import extract_algorithm_argument
from .whole_word import find_weak_crypto_tokens

# ---------------------------------------------------------------------------
# Rejection rules for the bare whole-word path (#2 below).
#
# The getInstance-argument path (#2a) and the structured api crypto_usage path
# (#1) are genuine first-party usage and are always kept. The bare whole-word
# path, however, fired on library-internal crypto-provider strings, dotted Java
# class descriptors and prose/log sentences (base_analys.md B6). The predicates
# below reject those so the bare path only counts a token as evidence when the
# string is plausibly first-party weak-crypto *usage*.
# ---------------------------------------------------------------------------

# A fully-qualified dotted Java class/package descriptor, e.g.
# ``org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD4``.
# Requires >= 3 dot-separated identifier segments (``pkg.pkg.Class``); inner
# classes (``$Inner``) are permitted inside the final segment. The smali ``L..;``
# form is already handled by ``looks_like_type_descriptor``.
_DOTTED_CLASS_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){2,}$")

# Crypto-provider registration / alias substrings (case-insensitive). These are
# JCA provider service-registration constants, never first-party usage:
#   ``Alg.Alias.Mac.RC2/CFB8``    -> alg.alias / .mac.
#   ``KeyStore.PKCS12-3DES-3DES`` -> keystore.
_PROVIDER_MARKERS = (
    "alg.alias",
    "keystore.",
    ".mac.",
    ".cipher.",
    ".messagedigest.",
    ".signature.",
    ".securerandom.",
    ".keygenerator.",
    ".keyfactory.",
    ".keypairgenerator.",
    ".secretkeyfactory.",
    ".algorithmparameters.",
    ".secretkeyfactory ",
)

# A provider *descriptor* string such as
# ``HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)`` - a provider
# name followed by a parenthesised list of the services it registers.
_PROVIDER_DESCRIPTOR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{2,}\s*\(.*\)\s*$")
_PROVIDER_DESCRIPTOR_WORDS = (
    "digest",
    "signature",
    "securerandom",
    "cipher",
    "keystore",
    "keygenerator",
    "mac",
)

# A run of >= 2 letters, used to decide whether a spaced string reads as prose.
_ALPHA_WORD_RE = re.compile(r"^[A-Za-z]{2,}$")
# Punctuation that signals code/algorithm shape rather than an English sentence.
_CODE_PUNCTUATION = frozenset("(){}\"'/=+*%<>|&")

# A JCA cipher/algorithm transformation SPEC such as ``DES/ECB/PKCS5Padding`` or
# ``AES/CBC/PKCS5Padding``: an algorithm name followed by one or more ``/``-
# separated mode/padding segments, no whitespace. A weak token inside such a
# spec is genuine first-party *usage* even without a ``getInstance()`` wrapper.
# By contrast a BARE algorithm-name token (``RC2``, ``Md5``, ``sha1``), an HTTP
# header name (``x-kik-content-md5``) or a spaced label (``RC2 Parameters``) is
# only a MENTION of an algorithm name, never usage (base_analys.md B6), so it
# must not fire the bare whole-word path.
_TRANSFORMATION_SPEC_RE = re.compile(r"^[A-Za-z0-9]+(?:/[A-Za-z0-9][\w.+-]*)+$")


def _looks_like_dotted_class(text: str) -> bool:
    """Return True if ``text`` is a fully-qualified dotted Java class descriptor."""
    token = text.strip()
    if not token or " " in token:
        return False
    if any(token.startswith(prefix) for prefix in FRAMEWORK_PREFIXES):
        return True
    return bool(_DOTTED_CLASS_RE.match(token))


def _looks_like_provider_registration(text: str) -> bool:
    """Return True if ``text`` is a JCA provider alias / registration constant."""
    lowered = text.lower()
    if any(marker in lowered for marker in _PROVIDER_MARKERS):
        return True
    stripped = text.strip()
    if _PROVIDER_DESCRIPTOR_RE.match(stripped):
        inner = stripped[stripped.index("(") + 1 :].lower()
        if ";" in inner or any(word in inner for word in _PROVIDER_DESCRIPTOR_WORDS):
            return True
    return False


def _looks_like_prose(text: str) -> bool:
    """Return True if ``text`` reads as a natural-language / log sentence.

    A weak-crypto token embedded in a spaced English phrase ("File MD5 check
    fail.", "Failed to get MD5") is not crypto usage. Algorithm identifiers and
    transformation strings ("DES", "DES/ECB/PKCS5Padding") carry no spaces and
    code/algorithm punctuation, so they are not treated as prose.
    """
    if " " not in text:
        return False
    if any(ch in _CODE_PUNCTUATION for ch in text):
        return False
    words = [part for part in re.split(r"[\s.,:;!?]+", text) if _ALPHA_WORD_RE.match(part)]
    return len(words) >= 2


def _is_library_or_prose_artifact(text: str) -> bool:
    """Return True if a bare string is a library/provider/prose artifact, not usage."""
    return (
        _looks_like_dotted_class(text)
        or _looks_like_provider_registration(text)
        or _looks_like_prose(text)
    )


def _looks_like_transformation_spec(text: str) -> bool:
    """Return True if ``text`` is an ``ALGO/MODE/PADDING`` cipher transformation spec.

    ``DES/ECB/PKCS5Padding`` / ``DES/CBC/NoPadding`` -> True (genuine usage spec).
    A bare token (``RC2``, ``Md5``, ``sha1``), a header (``x-kik-content-md5``)
    or a spaced label (``RC2 Parameters``) -> False (a mention, not usage).
    """
    token = text.strip()
    if not token or " " in token:
        return False
    return bool(_TRANSFORMATION_SPEC_RE.match(token))


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

            # Bare whole-word path (#2b): a mere MENTION of an algorithm name is
            # NOT weak-crypto usage (base_analys.md B6). A bare token (``RC2``,
            # ``Md5``, ``sha1``), an HTTP header name (``x-kik-content-md5``), a
            # ``<Algo> Parameters`` label, a dotted library class descriptor, a
            # JCA provider alias/registration constant or a prose/log sentence
            # must all be rejected. A whole-word token is only counted when the
            # bearing string is an actual cipher transformation SPEC in use
            # (``DES/ECB/PKCS5Padding``). NOTE: standalone slashed transformation
            # strings are already consumed upstream by ``looks_like_type_descriptor``
            # (they share the smali ``a/b/C`` shape), so in practice this path is a
            # conservative no-op guard: genuine first-party usage is captured
            # structurally by path #1 (crypto_usage) and path #2a (getInstance
            # argument), which remain the primary always-kept signals.
            if _is_library_or_prose_artifact(string):
                continue
            if not _looks_like_transformation_spec(string):
                continue

            tokens = find_weak_crypto_tokens(string)
            if tokens:
                evidence.append(f"Weak algorithm reference ({', '.join(tokens)}): {string[:70]}")

    return evidence
