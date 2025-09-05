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
String Analysis Filters Package.

Contains specialized filters for different string types including email addresses,
IP addresses, URLs, domain names, and Android system properties.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

from .android_properties_filter import AndroidPropertiesFilter
from .domain_filter import DomainFilter
from .email_filter import EmailFilter
from .network_filter import NetworkFilter

__all__ = ["EmailFilter", "NetworkFilter", "DomainFilter", "AndroidPropertiesFilter"]
