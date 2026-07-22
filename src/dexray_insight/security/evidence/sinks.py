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

"""API-sink catalog for evidence-required OWASP heuristics.

A *sink* is a real dangerous API call recorded by the ``api_invocation``
analysis module (``called_class`` / ``called_method``). Matching against a sink
is far stronger evidence than a substring co-occurrence over decompiled strings,
so the assessments use these helpers as their primary signal.

Class names are accepted in either smali (``Ljava/io/ObjectInputStream;``) or
dotted (``java.io.ObjectInputStream``) form; both normalise to the same value.
"""

import re
from typing import Any

# Sink kind -> list of (normalised class path, matching method fragments).
# An empty method tuple means "any method on this class is a sink".
SINK_CATALOG: dict[str, list[tuple[str, tuple[str, ...]]]] = {
    "sql": [
        ("android/database/sqlite/sqlitedatabase", ("rawquery", "execsql")),
        ("android/database/sqlite/sqlitequerybuilder", ()),
    ],
    "command": [
        ("java/lang/runtime", ("exec",)),
        ("java/lang/processbuilder", ()),
    ],
    "deserialization": [
        ("java/io/objectinputstream", ("readobject",)),
    ],
    "crypto": [
        ("javax/crypto/cipher", ("getinstance",)),
        ("java/security/messagedigest", ("getinstance",)),
        ("javax/crypto/keygenerator", ("getinstance",)),
        ("javax/crypto/secretkeyfactory", ("getinstance",)),
    ],
}

# Weaker command-execution signals: obfuscated malware routinely hides a real
# Runtime.exec behind reflection or a dynamically loaded dex. These should NOT
# be a hard precondition (that would blind the scanner), but they corroborate.
WEAK_COMMAND_SINKS: list[tuple[str, tuple[str, ...]]] = [
    ("java/lang/reflect/method", ("invoke",)),
    ("java/lang/class", ("forname",)),
    ("dalvik/system/dexclassloader", ()),
    ("dalvik/system/pathclassloader", ()),
    ("dalvik/system/inmemorydexclassloader", ()),
    ("java/lang/system", ("loadlibrary", "load")),
    ("java/lang/runtime", ("loadlibrary", "load")),
]

# Substrings that, when seen inside reflection_usage text, hint at command exec.
_REFLECTION_COMMAND_HINTS = ("runtime", "processbuilder", "exec", "/system/bin", "/bin/sh")


def _normalize_class(name: str) -> str:
    """Normalise a class name from smali or dotted form to slashed lowercase."""
    if not isinstance(name, str):
        return ""
    token = name.strip()
    if token.startswith("L") and token.endswith(";"):
        token = token[1:-1]
    token = token.replace(".", "/").replace("$", "/")
    return token.lower()


def _normalize_method(name: str) -> str:
    if not isinstance(name, str):
        return ""
    token = name.strip()
    # Drop a smali method descriptor tail such as "->exec" or "exec(...)".
    token = token.split("->")[-1]
    token = token.split("(")[0]
    return token.lower()


def _get_api_calls(analysis_results: dict[str, Any]) -> list:
    api_results = analysis_results.get("api_invocation", {}) if isinstance(analysis_results, dict) else {}
    api_data = api_results.to_dict() if hasattr(api_results, "to_dict") else api_results
    if not isinstance(api_data, dict):
        return []
    calls = api_data.get("api_calls", [])
    return calls if isinstance(calls, list) else []


def _get_reflection_usage(analysis_results: dict[str, Any]) -> list:
    api_results = analysis_results.get("api_invocation", {}) if isinstance(analysis_results, dict) else {}
    api_data = api_results.to_dict() if hasattr(api_results, "to_dict") else api_results
    if not isinstance(api_data, dict):
        return []
    usage = api_data.get("reflection_usage", [])
    return usage if isinstance(usage, list) else []


def _call_matches(call: dict, class_path: str, methods: tuple[str, ...]) -> bool:
    called_class = _normalize_class(call.get("called_class", ""))
    if class_path not in called_class:
        return False
    if not methods:
        return True
    called_method = _normalize_method(call.get("called_method", ""))
    return any(m in called_method for m in methods)


def list_sink_calls(analysis_results: dict[str, Any], kind: str) -> list[dict]:
    """Return the ``api_calls`` entries that match a sink of the given kind."""
    catalog = SINK_CATALOG.get(kind, [])
    if not catalog:
        return []
    matches = []
    for call in _get_api_calls(analysis_results):
        if not isinstance(call, dict):
            continue
        for class_path, methods in catalog:
            if _call_matches(call, class_path, methods):
                matches.append(call)
                break
    return matches


def has_sink(analysis_results: dict[str, Any], kind: str) -> bool:
    """Return True if at least one API sink of ``kind`` is present."""
    return bool(list_sink_calls(analysis_results, kind))


def list_weak_command_signals(analysis_results: dict[str, Any]) -> list[str]:
    """Return weaker command-execution signals (reflection / dynamic loading).

    These are intentionally *not* hard sinks: obfuscated malware hides a real
    ``Runtime.exec`` behind reflection or a runtime-loaded dex, so treating the
    absence of a hard sink as proof-of-safety would create false negatives.
    """
    signals: list[str] = []

    for call in _get_api_calls(analysis_results):
        if not isinstance(call, dict):
            continue
        for class_path, methods in WEAK_COMMAND_SINKS:
            if _call_matches(call, class_path, methods):
                signals.append(
                    f"{call.get('called_class', '')}.{call.get('called_method', '')}".strip(".")
                )
                break

    for entry in _get_reflection_usage(analysis_results):
        if isinstance(entry, str) and any(hint in entry.lower() for hint in _REFLECTION_COMMAND_HINTS):
            signals.append(f"Reflection command hint: {entry[:80]}")

    return signals


_ALGORITHM_ARG_RE = re.compile(r"""getInstance\s*\(\s*["']([^"']+)["']""", re.IGNORECASE)


def extract_algorithm_argument(text: str) -> str | None:
    """Extract the algorithm string from a ``getInstance("ALGO/...")`` call.

    Returns the raw argument (e.g. ``"DES/ECB/PKCS5Padding"``) or None.
    """
    if not isinstance(text, str):
        return None
    match = _ALGORITHM_ARG_RE.search(text)
    return match.group(1) if match else None
