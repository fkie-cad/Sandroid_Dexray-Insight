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
Library Detection Engines Package.

Contains specialized detection engines for different library detection methods.
Each engine follows Single Responsibility Principle and handles timing,
error management, and result processing for its detection method.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

from .androidx_engine import AndroidXDetectionEngine
from .apktool_detection_engine import ApktoolDetectionEngine
from .coordinator import LibraryDetectionCoordinator
from .heuristic_engine import HeuristicDetectionEngine
from .native_engine import NativeLibraryDetectionEngine
from .similarity_engine import SimilarityDetectionEngine

__all__ = [
    "HeuristicDetectionEngine",
    "SimilarityDetectionEngine",
    "NativeLibraryDetectionEngine",
    "AndroidXDetectionEngine",
    "ApktoolDetectionEngine",
    "LibraryDetectionCoordinator",
]
