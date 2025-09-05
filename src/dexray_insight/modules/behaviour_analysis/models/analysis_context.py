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

"""Behavior Analysis Context.

Extended context for behavior analysis with mode-specific
data and analysis coordination information.
"""

from dataclasses import dataclass
from typing import Any
from typing import Optional

from .behavior_evidence import BehaviorEvidence


@dataclass
class BehaviorAnalysisContext:
    """Extended context for behavior analysis operations."""

    # Analysis mode configuration
    analysis_mode: str  # 'fast' or 'deep'
    deep_mode_enabled: bool = False

    # Androguard objects for analysis
    apk_obj: Optional[Any] = None
    dex_obj: Optional[Any] = None
    dx_obj: Optional[Any] = None

    # Analysis state tracking
    analyzed_behaviors: list[str] = None
    total_evidence_found: int = 0
    analysis_start_time: Optional[float] = None

    # Configuration and settings
    config: Optional[dict[str, Any]] = None
    analyzer_settings: Optional[dict[str, Any]] = None

    # Results aggregation
    evidence_by_type: Optional[dict[str, list[BehaviorEvidence]]] = None
    high_confidence_evidence: Optional[list[BehaviorEvidence]] = None

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.analyzed_behaviors is None:
            self.analyzed_behaviors = []
        if self.evidence_by_type is None:
            self.evidence_by_type = {}
        if self.high_confidence_evidence is None:
            self.high_confidence_evidence = []

    def add_evidence(self, behavior_type: str, evidence: list[BehaviorEvidence]) -> None:
        """Add evidence for a specific behavior type."""
        if behavior_type not in self.evidence_by_type:
            self.evidence_by_type[behavior_type] = []

        self.evidence_by_type[behavior_type].extend(evidence)
        self.total_evidence_found += len(evidence)

        # Track high confidence evidence
        for ev in evidence:
            if ev.is_high_confidence():
                self.high_confidence_evidence.append(ev)

    def mark_behavior_analyzed(self, behavior_type: str) -> None:
        """Mark a behavior type as analyzed."""
        if behavior_type not in self.analyzed_behaviors:
            self.analyzed_behaviors.append(behavior_type)

    def get_evidence_summary(self) -> dict[str, int]:
        """Get summary of evidence by type."""
        summary = {}
        for behavior_type, evidence_list in self.evidence_by_type.items():
            summary[behavior_type] = len(evidence_list)
        return summary

    def get_high_confidence_count(self) -> int:
        """Get count of high confidence evidence."""
        return len(self.high_confidence_evidence)

    def is_deep_mode(self) -> bool:
        """Check if running in deep analysis mode."""
        return self.deep_mode_enabled and self.analysis_mode == "deep"

    def has_dex_objects(self) -> bool:
        """Check if DEX objects are available for analysis."""
        return self.dex_obj is not None and self.dx_obj is not None

    def get_analyzed_behavior_count(self) -> int:
        """Get count of analyzed behavior types."""
        return len(self.analyzed_behaviors)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for logging/debugging."""
        return {
            "analysis_mode": self.analysis_mode,
            "deep_mode_enabled": self.deep_mode_enabled,
            "analyzed_behaviors": self.analyzed_behaviors,
            "total_evidence_found": self.total_evidence_found,
            "high_confidence_count": self.get_high_confidence_count(),
            "has_dex_objects": self.has_dex_objects(),
            "evidence_summary": self.get_evidence_summary(),
        }
