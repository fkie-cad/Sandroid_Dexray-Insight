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

"""Core framework for Dexray Insight object-oriented analysis engine."""

from .analysis_engine import AnalysisEngine
from .analysis_engine import DependencyResolver
from .analysis_engine import ExecutionPlan
from .base_classes import AnalysisContext
from .base_classes import AnalysisSeverity
from .base_classes import AnalysisStatus
from .base_classes import BaseAnalysisModule
from .base_classes import BaseExternalTool
from .base_classes import BaseResult
from .base_classes import BaseSecurityAssessment
from .base_classes import ModuleRegistry
from .base_classes import SecurityFinding
from .base_classes import register_assessment
from .base_classes import register_module
from .base_classes import register_tool
from .base_classes import registry
from .configuration import Configuration
from .security_engine import SecurityAssessmentEngine
from .security_engine import SecurityAssessmentResults

__all__ = [
    "BaseAnalysisModule",
    "BaseExternalTool",
    "BaseSecurityAssessment",
    "AnalysisContext",
    "BaseResult",
    "AnalysisStatus",
    "AnalysisSeverity",
    "SecurityFinding",
    "ModuleRegistry",
    "registry",
    "register_module",
    "register_tool",
    "register_assessment",
    "AnalysisEngine",
    "ExecutionPlan",
    "DependencyResolver",
    "Configuration",
    "SecurityAssessmentEngine",
    "SecurityAssessmentResults",
]
