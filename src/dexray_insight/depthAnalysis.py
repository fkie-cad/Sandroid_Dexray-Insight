#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

import importlib
import logging
from .results.InDepthAnalysisResults import Results
from .Utils import androguardObjClass
from typing import Dict, Any

class apk_in_depth_analysis:

    def __init__(self, file_path, do_signature_check, apk_to_diff, is_verbose, exclude_net_libs, unzip_apk_path):
        self.apk_file_path = file_path
        self._analysis_results = {}
        self.apk_to_diff = apk_to_diff
        self.unzip_apk_path = unzip_apk_path
        self.do_signature_analysis = do_signature_check
        if is_verbose:
            logging.getLogger('androguard').setLevel(logging.WARNING)
        else:
            logging.getLogger("androguard").disabled = True
        self.androguard_obj = androguardObjClass.Androguard_Obj(file_path)
        self.verbose = is_verbose
        self.runtimes = set()  # TODO: This is just a workaround for testing. Other implementation strongly advised
        self.string_buff = [] # Currently used, so that in the dotnet analysis found strings in the .cs files can be analyzed without rewriting the code
        self.exclude_net_libs = exclude_net_libs


    def get_apk_file_path(self):
        return self.apk_file_path



    def analyze(self):
        """
        Perform analysis using specified modules.

        Args:
            do_signature_analysis (bool): Whether to include signature analysis.
        """

        # Base modules to always execute
        modules = [
            ("apkstaticanalysismonitor.api_invocation_analysis.api_analysis_module", "api_analysis_execute"),
            ("apkstaticanalysismonitor.manifest_analysis.manifest_analysis_module", "manifest_analysis_execute"),
            ("apkstaticanalysismonitor.string_analysis.string_analysis_module", "string_analysis_execute"),
            ("apkstaticanalysismonitor.permission_analysis.permission_analysis_module", "permission_analysis_execute"),
        ]

        # Conditionally add the signature analysis module
        if self.do_signature_analysis:
             modules.append(("apkstaticanalysismonitor.signature_detection.signature_detection_module", "signature_detection_execute"))

        if self.apk_to_diff is not None:
            modules.append(("apkstaticanalysismonitor.apk_diffing.apk_diffing_module", "apk_diffing_execute"))


        for module_name, method_name in modules:
            try:
               self._execute_module(module_name,method_name)
            except Exception as e:
                if self.verbose:
                    logging.error(f"Exception in method {method_name} in module {module_name}: {e}")



    def _execute_module(self, module_name: str, method_name: str):
        """
        Dynamically import and execute a method from a module.

        Args:
            module_name (str): The name of the module to import.
            method_name (str): The method to execute within the module.
        """
        try:
            # Dynamically import the module
            module = importlib.import_module(module_name)

            # Get the method from the module
            execute_method = getattr(module, method_name)
            logging.info(f"running {module_name}")

            # E.g. if the dotnet analysis finds strings, we want these strings to be analysed too
            if method_name == "string_analysis_execute":
                # Execute the method and store its results
                result = execute_method(self.apk_file_path, self.androguard_obj, self.string_buff)
            else:
                # Execute the method and store its results
                result = execute_method(self.apk_file_path,self.androguard_obj)

            # Only start the .NET analysis, if Mono Runtime is provided
            if method_name == "manifest_analysis_execute":
                if "mono.MonoRuntimeProvider" in result["Content Provider"]:
                    self.runtimes.add("dotnetMono")  # TODO: This is just a workaround for testing. Other implementation strongly advised
                    dotnet_module = importlib.import_module("apkstaticanalysismonitor.dotnetAnalysis")
                    # TODO: @Daniel: setattr(dotnet_module, "dlls_to_analyze", [...])
                    dotnet_analysis_execute = getattr(dotnet_module, "dotnet_analysis_execute")

                    logging.info(f"running apkstaticanalysismonitor.dotnetAnalysis")

                    dotnet_results = dotnet_analysis_execute(self.apk_file_path, self.androguard_obj, self.exclude_net_libs, self.unzip_apk_path)

                    self.string_buff.extend(dotnet_results["found_strings"])
                    self._analysis_results["dotnet_analysis_execute"] = dotnet_results["results"]


            # Store results in `_analysis_results` (or another field)
            self._analysis_results[method_name] = result
        except (ImportError, AttributeError, ModuleNotFoundError) as e:
            print(f"Error executing {method_name} from {module_name}: {e}")



    def _create_results(self, analysis_data: Dict[str, Any], apk_name: str) -> Results:
        """
        Creates a Results object from analysis data.

        Args:
            analysis_data (dict): Analysis data from `_analysis_results`.
            apk_name (str): Name of the APK file.

        Returns:
            Results: The populated Results object.
        """
        return Results(
            # we want only the results which are in depth analysis results
            intents=analysis_data.get("manifest_analysis_execute", {}).get("Intent Filters", []),
            filtered_permissions=analysis_data.get("permission_analysis_execute", []),
            signatures=analysis_data.get("signature_detection_execute", {"koodous": None, "vt": None, "triage": None}),
            strings_emails=analysis_data.get("string_analysis_execute", [[], [], [], []])[0],
            strings_ip=analysis_data.get("string_analysis_execute", [[], [], [], []])[1],
            strings_urls=analysis_data.get("string_analysis_execute", [[], [], [], []])[2],
            strings_domain=analysis_data.get("string_analysis_execute", [[], [], [], []])[3],
            strings_props=analysis_data.get("string_analysis_execute", [[], [], [], []])[4],
            dotnetMono_assemblies=analysis_data.get("dotnet_analysis_execute", [[], [], [], []])[0],
            apk_name=apk_name
        )

    
    def get_analysis_results(self):
        """
        Generate in-depth analysis results using `Results`.

        Returns:
            Results: The analysis results object.
        """
        return self._create_results(self._analysis_results, self.apk_file_path)


