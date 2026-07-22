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

"""Ranked / tiered security-report rendering (ranking primitives + Markdown writer)."""

from .markdown_report import MarkdownSecurityReporter
from .risk_ranking import finding_score
from .risk_ranking import rank_findings
from .risk_ranking import tier_findings
from .risk_ranking import top_risks

__all__ = [
    "MarkdownSecurityReporter",
    "finding_score",
    "rank_findings",
    "tier_findings",
    "top_risks",
]
