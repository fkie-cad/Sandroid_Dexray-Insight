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
Tracker Analysis Data Models.

Data models for representing detected trackers and analysis results.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

from dataclasses import dataclass
from typing import Any
from typing import Optional


@dataclass
class DetectedTracker:
    """Container for a detected tracker with metadata."""

    name: str
    version: Optional[str] = None
    description: str = ""
    category: str = ""
    website: str = ""
    code_signature: str = ""
    network_signature: str = ""
    detection_method: str = ""
    locations: list[str] = None
    confidence: float = 1.0

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.locations is None:
            self.locations = []

    def to_dict(self) -> dict[str, Any]:
        """Convert tracker to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "website": self.website,
            "code_signature": self.code_signature,
            "network_signature": self.network_signature,
            "detection_method": self.detection_method,
            "locations": self.locations,
            "confidence": self.confidence,
        }
