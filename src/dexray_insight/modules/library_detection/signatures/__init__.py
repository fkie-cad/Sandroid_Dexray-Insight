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
Library Detection Signatures Package.

Contains signature extraction and matching functionality for similarity-based detection.
Separated from main module for better maintainability and to support advanced
LibScan-style similarity analysis.
"""

from .class_signatures import ClassSignatureExtractor
from .signature_database import get_known_library_signatures
from .signature_matcher import SignatureMatcher

__all__ = ["ClassSignatureExtractor", "get_known_library_signatures", "SignatureMatcher"]
