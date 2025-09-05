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

"""Behaviour analysis results module for tracking detected application behaviors and features."""

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Optional

from ..core.base_classes import BaseResult


@dataclass
class BehaviourAnalysisFinding:
    """Represents a single behaviour analysis finding."""

    feature_name: str
    detected: bool
    evidence: list[dict[str, Any]] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            "feature_name": self.feature_name,
            "detected": self.detected,
            "evidence": self.evidence,
            "description": self.description,
        }


@dataclass
class BehaviourAnalysisResults(BaseResult):
    """Results class for behaviour analysis module."""

    findings: dict[str, BehaviourAnalysisFinding] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)
    androguard_objects: Optional[dict[str, Any]] = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Convert results to dictionary format."""
        base_dict = super().to_dict()
        base_dict.update(
            {
                "findings": {name: finding.to_dict() for name, finding in self.findings.items()},
                "summary": self.summary,
                # Note: androguard_objects are not serialized as they contain binary objects
            }
        )
        return base_dict

    def add_finding(
        self, feature_name: str, detected: bool, evidence: list[dict[str, Any]] = None, description: str = ""
    ):
        """Add a finding to the results."""
        if evidence is None:
            evidence = []
        self.findings[feature_name] = BehaviourAnalysisFinding(
            feature_name=feature_name, detected=detected, evidence=evidence, description=description
        )

    def get_detected_features(self) -> list[str]:
        """Get list of detected feature names."""
        return [name for name, finding in self.findings.items() if finding.detected]

    def get_terminal_summary(self) -> str:
        """Get brief summary for terminal output."""
        detected = self.get_detected_features()
        if not detected:
            return "🔍 Behaviour Analysis: No suspicious behaviors detected"

        summary_parts = []
        for feature in detected:
            summary_parts.append(f"✓ {feature}")

        return f"🔍 Behaviour Analysis: {len(detected)} behaviors detected:\n" + "\n".join(
            f"  {part}" for part in summary_parts
        )
