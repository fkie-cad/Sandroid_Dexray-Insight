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

"""Whole-word algorithm-token matching.

Historically weak-crypto detection matched the substring ``des`` inside
``Descriptor`` / ``desktop`` / ``adDescriptor.bids`` and ``md5`` /
``sha1`` anywhere. Matching an algorithm token as a *whole word* removes those
false positives while still catching ``DES/ECB/PKCS5Padding`` and
``MessageDigest.getInstance("MD5")``.
"""

import re

# Weak / deprecated cryptographic algorithm tokens flagged by the assessments.
WEAK_CRYPTO_TOKENS = ("DES", "3DES", "RC4", "RC2", "MD5", "MD4", "MD2", "SHA1", "SHA-1")

_COMPILED_TOKEN_CACHE: dict[str, re.Pattern] = {}


def _compiled(token: str) -> re.Pattern:
    pattern = _COMPILED_TOKEN_CACHE.get(token)
    if pattern is None:
        # \b handles ASCII word boundaries; SHA-1 / SHA1 both need matching, so
        # anchor on non-word-adjacent boundaries around the escaped token.
        pattern = re.compile(rf"(?<![\w]){re.escape(token)}(?![\w])", re.IGNORECASE)
        _COMPILED_TOKEN_CACHE[token] = pattern
    return pattern


def matches_algorithm_token(text: str, token: str) -> bool:
    """Return True if ``token`` occurs as a whole word inside ``text``.

    ``matches_algorithm_token("DES/ECB/PKCS5Padding", "DES")`` -> True
    ``matches_algorithm_token("SomeDescriptor", "DES")``       -> False
    ``matches_algorithm_token("adDescriptor.bids", "DES")``    -> False
    """
    if not isinstance(text, str) or not token:
        return False
    return _compiled(token).search(text) is not None


def find_weak_crypto_tokens(text: str) -> list[str]:
    """Return the weak-crypto tokens that occur as whole words in ``text``."""
    if not isinstance(text, str) or not text:
        return []
    return [token for token in WEAK_CRYPTO_TOKENS if matches_algorithm_token(text, token)]
