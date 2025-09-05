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

"""Library Detection Module - Backward Compatibility Layer.

This file maintains backward compatibility for existing imports while
delegating to the new submodule structure.

Phase 6.5 TDD Refactoring: Maintains API compatibility while using
refactored submodule architecture internally.
"""

# Import everything from the new submodule structure
from .library_detection.library_detection_module import LibraryDetectionModule
from .library_detection.library_detection_module import LibraryDetectionResult
from .library_detection.patterns import LIBRARY_PATTERNS

# Re-export the main classes and functions to maintain compatibility
__all__ = ["LibraryDetectionModule", "LibraryDetectionResult", "LIBRARY_PATTERNS"]
