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

"""Evidence primitives for evidence-required OWASP heuristics.

This package centralises the small, well-tested predicates that let the OWASP
security assessments distinguish *evidence-backed* findings (API sinks, manifest
facts, whole-word algorithm references inside a crypto factory argument) from
*substring co-occurrence* over decompiled strings, which historically produced a
flood of false positives on benign apps (JVM type descriptors, common class
names, etc.).

Responsibilities are split by concern:

* :mod:`descriptors` - is a string a code identifier / JVM type descriptor?
* :mod:`whole_word`   - whole-word (not substring) algorithm-token matching.
* :mod:`sinks`        - an API-sink catalog matched against ``api_invocation``.
"""

from .crypto import collect_weak_crypto_evidence
from .descriptors import is_probably_code_identifier
from .descriptors import is_probably_placeholder
from .descriptors import looks_like_type_descriptor
from .package_allowlist import FRAMEWORK_PREFIXES
from .package_allowlist import carries_browsable_or_custom_scheme
from .package_allowlist import classify_component
from .package_allowlist import should_downrank
from .pii_taxonomy import ART9_TOKENS
from .pii_taxonomy import ENCRYPTION_AT_REST_TOKENS
from .pii_taxonomy import LIBRARY_EMAIL_DOMAINS
from .pii_taxonomy import PERMISSION_SINK_MAP
from .pii_taxonomy import PII_TAXONOMY
from .pii_taxonomy import PRIVATE_KEY_PREF_TOKENS
from .pii_taxonomy import SENSITIVE_COLUMN_TOKENS
from .pii_taxonomy import SENSITIVE_PREF_KEY_TOKENS
from .pii_taxonomy import PIICategory
from .pii_taxonomy import PIIPattern
from .pii_taxonomy import PIIValidator
from .pii_taxonomy import PIIVerdict
from .pii_taxonomy import is_placeholder_or_library_email
from .sinks import extract_algorithm_argument
from .sinks import has_sink
from .sinks import list_sink_calls
from .sinks import list_weak_command_signals
from .whole_word import WEAK_CRYPTO_TOKENS
from .whole_word import find_weak_crypto_tokens
from .whole_word import matches_algorithm_token

__all__ = [
    "is_probably_code_identifier",
    "is_probably_placeholder",
    "looks_like_type_descriptor",
    "matches_algorithm_token",
    "find_weak_crypto_tokens",
    "WEAK_CRYPTO_TOKENS",
    "has_sink",
    "list_sink_calls",
    "list_weak_command_signals",
    "extract_algorithm_argument",
    "collect_weak_crypto_evidence",
    "classify_component",
    "should_downrank",
    "carries_browsable_or_custom_scheme",
    "FRAMEWORK_PREFIXES",
    "PIICategory",
    "PIIPattern",
    "PIIVerdict",
    "PIIValidator",
    "PII_TAXONOMY",
    "PERMISSION_SINK_MAP",
    "ART9_TOKENS",
    "ENCRYPTION_AT_REST_TOKENS",
    "SENSITIVE_COLUMN_TOKENS",
    "SENSITIVE_PREF_KEY_TOKENS",
    "PRIVATE_KEY_PREF_TOKENS",
    "LIBRARY_EMAIL_DOMAINS",
    "is_placeholder_or_library_email",
]
