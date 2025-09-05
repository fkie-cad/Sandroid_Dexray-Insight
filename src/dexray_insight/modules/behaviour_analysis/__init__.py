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
Behaviour Analysis Module.

This package provides comprehensive behavioral analysis for Android applications,
supporting both fast mode (APK-only) and deep mode (full DEX analysis).

Components:
- analyzers: Privacy-sensitive behavior detection modules
- engines: Pattern search and analysis coordination
- modes: Mode-specific analysis logic (fast/deep)
- models: Data structures and behavior models
"""

from .behaviour_analysis_module import BehaviourAnalysisModule

__all__ = ["BehaviourAnalysisModule"]
