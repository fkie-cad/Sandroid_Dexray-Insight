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
Library Detection Module Package.

Third-party library detection module using multi-stage analysis with specialized engines.
Refactored into submodules following Single Responsibility Principle.

Phase 6.5 TDD Refactoring: Split from monolithic library_detection.py into:
- patterns/: Library pattern definitions for heuristic detection
- signatures/: Signature extraction and matching for similarity detection
- engines/: Specialized detection engines with timing and error management

Main Components:
- LibraryDetectionModule: Main analysis module
- LibraryDetectionResult: Result data structure
"""

from .engines import AndroidXDetectionEngine
from .engines import HeuristicDetectionEngine
from .engines import LibraryDetectionCoordinator
from .engines import NativeLibraryDetectionEngine
from .engines import SimilarityDetectionEngine
from .library_detection_module import LibraryDetectionModule
from .library_detection_module import LibraryDetectionResult
from .patterns import LIBRARY_PATTERNS
from .signatures import ClassSignatureExtractor
from .signatures import SignatureMatcher
from .signatures import get_known_library_signatures

__all__ = [
    "LibraryDetectionModule",
    "LibraryDetectionResult",
    "LIBRARY_PATTERNS",
    "ClassSignatureExtractor",
    "SignatureMatcher",
    "get_known_library_signatures",
    "HeuristicDetectionEngine",
    "SimilarityDetectionEngine",
    "NativeLibraryDetectionEngine",
    "AndroidXDetectionEngine",
    "LibraryDetectionCoordinator",
]
