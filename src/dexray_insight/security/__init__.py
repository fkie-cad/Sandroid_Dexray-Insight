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

"""OWASP Top 10 security assessment modules for Dexray Insight."""

# Import all security assessments to register them
from . import authentication_failures_assessment
from . import broken_access_control_assessment
from . import cve_assessment
from . import injection_assessment
from . import insecure_design_assessment
from . import integrity_failures_assessment
from . import logging_monitoring_failures_assessment
from . import mobile_specific_assessment
from . import security_misconfiguration_assessment
from . import sensitive_data_assessment
from . import ssrf_assessment
from . import vulnerable_components_assessment

__all__ = [
    "injection_assessment",
    "broken_access_control_assessment",
    "sensitive_data_assessment",
    "insecure_design_assessment",
    "security_misconfiguration_assessment",
    "vulnerable_components_assessment",
    "authentication_failures_assessment",
    "integrity_failures_assessment",
    "logging_monitoring_failures_assessment",
    "ssrf_assessment",
    "mobile_specific_assessment",
    "cve_assessment",
]
