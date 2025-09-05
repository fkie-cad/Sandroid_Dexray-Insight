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
String Analysis Module Package.

String extraction and analysis module using specialized filters and extractors.
Refactored into submodules following Single Responsibility Principle.

Phase 8 TDD Refactoring: Split from monolithic string_analysis.py into:
- extractors/: String extraction engines for different APK components
- filters/: Specialized filters for different string types (email, IP, URL, domain, android properties)
- validators/: Common validation utilities for string pattern validation

Main Components:
- StringAnalysisModule: Main analysis module
- StringAnalysisResult: Result data structure
"""

from .extractors import StringExtractor
from .filters import AndroidPropertiesFilter
from .filters import DomainFilter
from .filters import EmailFilter
from .filters import NetworkFilter
from .string_analysis_module import StringAnalysisModule
from .string_analysis_module import StringAnalysisResult
from .validators import StringValidators

__all__ = [
    "StringAnalysisModule",
    "StringAnalysisResult",
    "StringExtractor",
    "EmailFilter",
    "NetworkFilter",
    "DomainFilter",
    "AndroidPropertiesFilter",
    "StringValidators",
]
