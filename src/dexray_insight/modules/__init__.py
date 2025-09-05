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

"""Analysis modules for Dexray Insight using the new OOP framework."""

# Import all refactored modules to register them
from . import api_invocation_analysis
from . import apk_overview_analysis
from . import behaviour_analysis
from . import dotnet_analysis
from . import library_detection
from . import manifest_analysis
from . import native  # Native binary analysis modules
from . import permission_analysis
from . import signature_analysis
from . import string_analysis
from . import tracker_analysis

__all__ = [
    "apk_overview_analysis",
    "signature_analysis",
    "permission_analysis",
    "string_analysis",
    "manifest_analysis",
    "api_invocation_analysis",
    "tracker_analysis",
    "behaviour_analysis",
    "dotnet_analysis",
    "library_detection",
    "native",
]
