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

"""Androguard object wrapper classes for APK analysis.

This module provides wrapper classes for Androguard objects to standardize
APK, DEX, and analysis object access across the Dexray Insight framework.
"""

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

import logging

from androguard.misc import AnalyzeAPK
from loguru import logger


class Androguard_Obj:
    """Wrapper class for Androguard APK analysis objects."""

    def __init__(self, apk_path):
        """Initialize Androguard analysis objects from APK path."""
        logging.getLogger("androguard").disabled = True

        # just suppresing the messages from androguard
        logger.remove()
        # logger.add(sys.stderr, level="WARNING")

        # MULTIDEX FIX: Ensure all DEX files are processed
        # The AnalyzeAPK function should handle multidex automatically,
        # but we need to verify this is working correctly
        try:
            apk, dex_obj, dx_analysis = AnalyzeAPK(apk_path)

            # Debug logging for multidex handling
            debug_logger = logging.getLogger(__name__)
            debug_logger.debug(f"Androguard initialized with {len(dex_obj) if dex_obj else 0} DEX files")

            # Verify multidex handling
            if dex_obj and len(dex_obj) > 1:
                debug_logger.debug(f"✅ Multidex APK detected: {len(dex_obj)} DEX files")
                for i, dex in enumerate(dex_obj):
                    strings_count = len(dex.get_strings()) if hasattr(dex, "get_strings") else 0
                    debug_logger.debug(f"   DEX {i+1}: {strings_count} strings")
            elif dex_obj and len(dex_obj) == 1:
                debug_logger.debug("Single DEX APK detected")
            else:
                debug_logger.warning("⚠️  No DEX objects found in APK analysis")

            self.androguard_apk = apk
            self.androguard_dex = dex_obj
            self.androguard_analysisObj = dx_analysis

        except Exception as e:
            debug_logger = logging.getLogger(__name__)
            debug_logger.error(f"Androguard analysis failed: {str(e)}")
            # Set defaults to prevent crashes
            self.androguard_apk = None
            self.androguard_dex = []
            self.androguard_analysisObj = None
            raise

    # Getter for androguard_apk
    def get_androguard_apk(self):
        """Get the Androguard APK object."""
        return self.androguard_apk

    # Getter for androguard_dex
    def get_androguard_dex(self):
        """Get the Androguard DEX objects list."""
        return self.androguard_dex

    def get_androguard_analysisObj(self):
        """Get the Androguard analysis object."""
        return self.androguard_analysisObj
