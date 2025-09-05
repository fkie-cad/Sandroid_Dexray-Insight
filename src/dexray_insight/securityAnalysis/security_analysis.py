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

"""Security analysis module for runtime-specific security assessment."""

import logging

from ..results.SecurityAnalysisResults import SecurityAnalysisResults
from ..Utils import androguardObjClass
from .runtimes import dexSec
from .runtimes import dotnetMonoSec


class security_analysis:
    """Runtime-specific security analysis coordinator."""

    def __init__(self, runtimes: set, file_path, dll_target_dir):
        """Initialize security analysis with target runtimes and paths.

        Args:
            runtimes: Set of runtime types to analyze
            file_path: Path to APK file
            dll_target_dir: Target directory for DLL extraction
        """
        runtimes.add("dex")  # DEX security analysis should always be performed
        self.runtimes = runtimes
        self.dll_target_dir = dll_target_dir
        self.results = SecurityAnalysisResults()
        self.androguard_obj = androguardObjClass.Androguard_Obj(file_path)
        self._APP_NAME = self.androguard_obj.androguard_apk.get_app_name().replace(
            " ", ""
        )  # TODO: .replace(...) not very stable

    def analyze(self):
        """Execute security analysis for all configured runtimes.

        Returns:
            SecurityAnalysisResults: Aggregated security analysis results
        """
        try:
            if self.runtimes:
                for r in self.runtimes:
                    self.run_runtime_specific_analysis(r)
            return self.results
        except Exception as e:
            logging.error(f"Exception during security analysis {e}")

    def run_runtime_specific_analysis(self, runtime):
        """Run security analysis for a specific runtime environment.

        Args:
            runtime: Runtime type to analyze ('dex', 'dotnetMono')

        Returns:
            Runtime-specific analysis results
        """
        try:
            if runtime == "dotnetMono":
                self.results.dotnet_results, bug_cnt = dotnetMonoSec.execute_dotnet_mono_security_analysis(
                    self._APP_NAME, self.dll_target_dir
                )
                print(f"[*] Identified {bug_cnt} security bugs inside the Xamarin based code")
            elif runtime == "dex":
                self.results.dex_results = dexSec.execute_dex_security_analysis()
            else:
                logging.info(f"No security analysis support for {runtime} available")
                self.results.additional_data.update(
                    {f"Couldn't analyse runtime {runtime}": f"No security analysis support for {runtime} available"}
                )
        except Exception as e:
            logging.error(f"Exception during security analysis of: {runtime}, Error: {e}")
