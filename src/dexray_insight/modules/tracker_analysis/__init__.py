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
Tracker Analysis Module Package.

Advertising and analytics tracker detection module using multi-stage analysis with specialized detectors.
Refactored into submodules following Single Responsibility Principle.

Phase 7 TDD Refactoring: Split from monolithic tracker_analysis.py into:
- databases/: Tracker pattern databases and Exodus Privacy API integration
- detectors/: Specialized detection engines for pattern matching, version extraction, and deduplication
- models/: Data models and result structures

Main Components:
- TrackerAnalysisModule: Main analysis module
- TrackerAnalysisResult: Result data structure
- DetectedTracker: Individual tracker representation
"""

from .databases import ExodusAPIClient
from .databases import TrackerDatabase
from .detectors import PatternDetector
from .detectors import TrackerDeduplicator
from .detectors import VersionExtractor
from .models import DetectedTracker
from .tracker_analysis_module import TrackerAnalysisModule
from .tracker_analysis_module import TrackerAnalysisResult

__all__ = [
    "TrackerAnalysisModule",
    "TrackerAnalysisResult",
    "DetectedTracker",
    "TrackerDatabase",
    "ExodusAPIClient",
    "PatternDetector",
    "VersionExtractor",
    "TrackerDeduplicator",
]
