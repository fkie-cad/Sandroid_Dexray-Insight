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
import threading

from androguard.core import apk as androguard_apk_module
from androguard.core import dex as androguard_dex_module
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler import decompiler as androguard_decompiler
from loguru import logger


class AndroguardObj:
    """Wrapper class for Androguard APK analysis objects.

    Construction mirrors :func:`androguard.misc.AnalyzeAPK` but defers the single
    most expensive step — ``Analysis.create_xref()`` — until it is actually
    needed. Cross-references are only consumed by modules that walk the call
    graph (``api_invocation``, disabled by default, and behaviour analysis in
    ``--deep`` mode). On a default run the xref build is skipped entirely, which
    is by far the largest wall-clock saving for large/multidex APKs. The
    APK object, DEX objects and per-DEX decompilers are still built eagerly, so
    ``get_strings()``, manifest/permission access and class/method traversal are
    unaffected.
    """

    def __init__(self, apk_path):
        """Initialize Androguard analysis objects from APK path (xref deferred)."""
        logging.getLogger("androguard").disabled = True

        # just suppresing the messages from androguard
        logger.remove()
        # logger.add(sys.stderr, level="WARNING")

        debug_logger = logging.getLogger(__name__)

        # Guards the lazy create_xref() build against concurrent module threads.
        self._xref_lock = threading.Lock()
        self._xref_built = False

        # MULTIDEX FIX: process every DEX (get_all_dex yields all of them).
        try:
            apk = androguard_apk_module.APK(apk_path)

            # Replicate AnalyzeAPK's setup WITHOUT create_xref(): build the APK,
            # every DalvikVMFormat/DEX, register them in a single Analysis and
            # attach the DAD decompiler. Cross-references are built lazily later.
            dex_obj = []
            dx_analysis = Analysis()
            for dex_bytes in apk.get_all_dex():
                df = androguard_dex_module.DEX(dex_bytes, using_api=apk.get_target_sdk_version())
                dx_analysis.add(df)
                dex_obj.append(df)
                df.set_decompiler(androguard_decompiler.DecompilerDAD(df, dx_analysis))

            # Debug logging for multidex handling (only when DEBUG is enabled so
            # the extra get_strings() scans are not paid on normal runs).
            if debug_logger.isEnabledFor(logging.DEBUG):
                debug_logger.debug(f"Androguard initialized with {len(dex_obj)} DEX files")
                if len(dex_obj) > 1:
                    debug_logger.debug(f"✅ Multidex APK detected: {len(dex_obj)} DEX files")
                    for i, dex in enumerate(dex_obj):
                        strings_count = len(dex.get_strings()) if hasattr(dex, "get_strings") else 0
                        debug_logger.debug(f"   DEX {i+1}: {strings_count} strings")
                elif len(dex_obj) == 1:
                    debug_logger.debug("Single DEX APK detected")
                else:
                    debug_logger.warning("⚠️  No DEX objects found in APK analysis")

            self.androguard_apk = apk
            self.androguard_dex = dex_obj
            self.androguard_analysisObj = dx_analysis

        except Exception as e:
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

    def get_androguard_analysis_obj(self):
        """Get the Androguard Analysis object, building cross-references on first use.

        ``create_xref()`` is the dominant cost of ``AnalyzeAPK`` and is only
        required by callers that traverse cross-references. It is built here,
        once, on first access (thread-safe), so runs that never need xref never
        pay for it.
        """
        if self.androguard_analysisObj is None:
            return None
        if not self._xref_built:
            with self._xref_lock:
                if not self._xref_built:
                    logging.getLogger(__name__).debug(
                        "Building Androguard cross-references (create_xref) on first use..."
                    )
                    self.androguard_analysisObj.create_xref()
                    self._xref_built = True
        return self.androguard_analysisObj
