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
Pattern Search Engine.

Provides centralized pattern matching capabilities for behavior analysis.
Handles searching through DEX strings, smali code, and other APK components.
"""

import logging
import re

from ..models.behavior_evidence import BehaviorEvidence


class PatternSearchEngine:
    """Centralized pattern search engine for behavior analysis.

    Deep-mode behaviour analysis invokes this engine many times (once per
    analyzed behaviour). The DEX string pool and the decompiled smali source
    corpus are identical across all of those calls, so they are extracted at
    most once per engine instance and reused. Share a single engine instance
    across the analyzers within one analysis to get the benefit (see
    ``BehaviourAnalysisModule._perform_deep_analysis``).
    """

    def __init__(self, logger: logging.Logger | None = None, context=None):
        """Initialize PatternSearchEngine with optional logger and context.

        Args:
            logger: Optional logger instance.
            context: Optional AnalysisContext. When provided, the shared,
                already-cached DEX string pool (``context.get_dex_strings_by_index``)
                is reused instead of re-scanning ``dex_obj`` on every call.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.context = context
        # Lazily-built, reused-across-calls corpora (deep mode only).
        self._string_corpus_by_index: list[list[str]] | None = None
        self._smali_corpus: list[tuple[int, str, str]] | None = None

    def _get_string_corpus(self, dex_obj) -> list[list[str]]:
        """Return DEX strings grouped by DEX index, built once and reused.

        Prefers the shared, cached string pool on the context (so the string
        pool is extracted a single time for the whole analysis). Falls back to
        iterating ``dex_obj`` directly when no context is available, preserving
        standalone behaviour. The per-DEX grouping keeps the exact
        ``dex_index`` / ``location`` provenance the analyzers rely on.
        """
        if self._string_corpus_by_index is not None:
            return self._string_corpus_by_index

        groups: list[list[str]] | None = None
        if self.context is not None:
            try:
                groups = self.context.get_dex_strings_by_index()
            except Exception as e:
                self.logger.debug(f"Falling back to per-DEX string extraction: {e}")
                groups = None

        if groups is None:
            groups = []
            if dex_obj:
                for i, dex in enumerate(dex_obj):
                    try:
                        groups.append([str(s) for s in dex.get_strings()])
                    except Exception as e:
                        self.logger.debug(f"Error extracting DEX strings for group {i}: {e}")
                        groups.append([])

        self._string_corpus_by_index = groups
        return self._string_corpus_by_index

    def _get_smali_corpus(self, dex_obj) -> list[tuple[int, str, str]]:
        """Return decompiled smali sources, built once and reused.

        This is the expensive step: it calls ``cls.get_source()`` over every
        class in every DEX. It is performed a single time per engine instance
        and cached as ``(dex_index, class_name, class_source)`` tuples so the
        exact class/line/dex provenance is preserved for later matching.
        """
        if self._smali_corpus is not None:
            return self._smali_corpus

        corpus: list[tuple[int, str, str]] = []
        if dex_obj:
            for i, dex in enumerate(dex_obj):
                try:
                    for cls in dex.get_classes():
                        class_source = cls.get_source()
                        if class_source:
                            corpus.append((i, cls.get_name(), class_source))
                except Exception as e:
                    self.logger.debug(f"Error collecting smali sources in DEX {i}: {e}")

        self._smali_corpus = corpus
        return self._smali_corpus

    def _match_strings(self, dex_obj, patterns: list[str]) -> list[BehaviorEvidence]:
        """Match patterns against the (once-built) DEX string corpus."""
        evidence = []
        for i, group in enumerate(self._get_string_corpus(dex_obj)):
            for string_val in group:
                for pattern in patterns:
                    if re.search(pattern, string_val, re.IGNORECASE):
                        evidence.append(
                            BehaviorEvidence(
                                type="string",
                                content=string_val,
                                pattern_matched=pattern,
                                location=f"DEX {i+1} strings",
                                dex_index=i,
                            )
                        )
        return evidence

    def _match_code(self, dex_obj, patterns: list[str]) -> list[BehaviorEvidence]:
        """Match patterns against the (once-built) smali source corpus."""
        evidence = []
        for i, class_name, class_source in self._get_smali_corpus(dex_obj):
            for pattern in patterns:
                for match in re.finditer(pattern, class_source, re.IGNORECASE):
                    # Get line number context
                    lines = class_source[: match.start()].count("\n")
                    evidence.append(
                        BehaviorEvidence(
                            type="code",
                            content=match.group(),
                            pattern_matched=pattern,
                            class_name=class_name,
                            line_number=lines + 1,
                            dex_index=i,
                        )
                    )
        return evidence

    def search_patterns_in_apk(
        self, apk_obj, dex_obj, dx_obj, patterns: list[str], feature_name: str
    ) -> list[BehaviorEvidence]:
        """Search patterns in APK strings and code."""
        evidence = []

        try:
            # Only scan when DEX objects are present (fast mode passes None).
            if dex_obj:
                evidence.extend(self._match_strings(dex_obj, patterns))
                evidence.extend(self._match_code(dex_obj, patterns))

            return evidence

        except Exception as e:
            self.logger.error(f"Pattern search failed for {feature_name}: {e}")
            return []

    def search_in_strings(self, dex_obj, patterns: list[str], feature_name: str) -> list[BehaviorEvidence]:
        """Search patterns only in DEX strings."""
        if not dex_obj:
            return []

        try:
            return self._match_strings(dex_obj, patterns)
        except Exception as e:
            self.logger.error(f"String search failed for {feature_name}: {e}")
            return []

    def search_in_code(self, dex_obj, patterns: list[str], feature_name: str) -> list[BehaviorEvidence]:
        """Search patterns only in smali code."""
        if not dex_obj:
            return []

        try:
            return self._match_code(dex_obj, patterns)
        except Exception as e:
            self.logger.error(f"Code search failed for {feature_name}: {e}")
            return []

    def check_permissions(self, apk_obj, permission_list: list[str]) -> list[BehaviorEvidence]:
        """Check for specific permissions in the APK."""
        evidence = []

        try:
            permissions = apk_obj.get_permissions()
            for permission in permission_list:
                if permission in permissions:
                    evidence.append(
                        BehaviorEvidence(type="permission", content=permission, location="AndroidManifest.xml")
                    )
        except Exception as e:
            self.logger.error(f"Permission check failed: {e}")

        return evidence
