#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from .runtimes import dotnetMonoSec, dexSec
from ..results.SecurityAnalysisResults import SecurityAnalysisResults
from ..Utils import androguardObjClass


class security_analysis:

    def __init__(self, runtimes: set, file_path, dll_target_dir):
        runtimes.add("dex") # DEX security analysis should always be performed
        self.runtimes =  runtimes
        self.dll_target_dir = dll_target_dir
        self.results = SecurityAnalysisResults()
        self.androguard_obj = androguardObjClass.Androguard_Obj(file_path)
        self._APP_NAME = self.androguard_obj.androguard_apk.get_app_name().replace(" ", "")   # TODO: .replace(...) not very stable

    def analyze(self):
        try:
            if self.runtimes:
                for r in self.runtimes:
                    self.run_runtime_specific_analysis(r)
            return self.results
        except Exception as e:
            logging.error(f"Exception during security analysis {e}")

    def run_runtime_specific_analysis(self, runtime):
        try:
            if runtime == "dotnetMono":
                self.results.dotnet_results, bug_cnt = dotnetMonoSec.execute_dotnet_mono_security_analysis(self._APP_NAME, self.dll_target_dir)
                print(f"[*] Identified {bug_cnt} security bugs inside the Xamarin based code")
            elif runtime == "dex":
                self.results.dex_results = dexSec.execute_dex_security_analysis()
            else:
                logging.info(f"No security analysis support for {runtime} available")
                self.results.additional_data.update({f"Couldn't analyse runtime {runtime}": f"No security analysis support for {runtime} available"})
        except Exception as e:
            logging.error(f"Exception during security analysis of: {runtime}, Error: {e}")


