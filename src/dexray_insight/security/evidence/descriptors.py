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

"""Predicates that classify a decompiled string as code, not data.

The OWASP string heuristics used to fire on smali type descriptors such as
``Landroidx/.../DeleteSurroundingTextCommand;`` and on bare class/method
identifiers. These predicates let a caller drop such tokens before treating a
string as a real query / command / secret.
"""

import re

# A JVM field/type descriptor, e.g. ``Ljava/lang/String;`` or ``[[Lcom/x/Y;``.
_TYPE_DESCRIPTOR_RE = re.compile(r"^\[*L[\w/$]+;$")

# A slashed class token (smali internal name), optionally ``;``-terminated and
# optionally with array prefixes, e.g. ``androidx/compose/Foo`` or ``Foo/Bar;``.
_SLASHED_CLASS_RE = re.compile(r"^\[*[\w$]+(?:/[\w$]+)+;?$")

# Characters that, if present, mean a string is not a single bare identifier:
# whitespace plus SQL / shell / expression operators.
_NON_IDENTIFIER_CHARS = frozenset(" \t\r\n\"'`;|&<>(){}[]=+*%,?")

# Common placeholder / template values that are never real secrets or evidence.
_PLACEHOLDER_RE = re.compile(
    r"^(?:test|example|sample|demo|placeholder|dummy|fake|mock|stub|"
    r"your_?(?:api_?key|token|secret)|insert_?key_?here|api_?key_?here|"
    r"replace_?with|null|undefined|none|nil|empty|xxx+|yyy+)",
    re.IGNORECASE,
)


def looks_like_type_descriptor(s: str) -> bool:
    """Return True if ``s`` is a JVM type descriptor or slashed class token.

    Examples that return True::

        Ljava/lang/String;
        [Lcom/example/Foo;
        Landroidx/.../DeleteSurroundingTextCommand;
        androidx/compose/ui/Modifier
    """
    if not isinstance(s, str):
        return False
    token = s.strip()
    if not token:
        return False
    if _TYPE_DESCRIPTOR_RE.match(token):
        return True
    return bool(_SLASHED_CLASS_RE.match(token))


def is_probably_code_identifier(s: str) -> bool:
    """Return True if ``s`` is a single bare code identifier (no data shape).

    A real SQL query / shell command / URL has whitespace and/or operators; a
    class name, method name, or field descriptor does not. Type descriptors are
    also treated as code identifiers.
    """
    if not isinstance(s, str):
        return False
    token = s.strip()
    if not token:
        return False
    if looks_like_type_descriptor(token):
        return True
    return not any(c in _NON_IDENTIFIER_CHARS for c in token)


def is_probably_placeholder(s: str) -> bool:
    """Return True if ``s`` is an obvious placeholder / template value."""
    if not isinstance(s, str):
        return False
    return bool(_PLACEHOLDER_RE.match(s.strip()))
