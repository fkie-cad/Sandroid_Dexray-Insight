#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

import json
import logging
from loguru import logger
from .results.apkInsightResults import APKInsightResults

def _parse_apkInsights_results(raw_json: str) -> APKInsightResults:
    """
    Parse APKInsight JSON output into an APKInsightResults object.

    Args:
        raw_json (str): The JSON output from APKInsight as a string.
        raw_output (str): The raw text output from APKInsight.

    Returns:
        APKInsightResults: A populated APKInsightResults object.
    """
    try:
        data = json.loads(raw_json)

        is_packed = data.get("is_packed", False)
        unpacked = data.get("unpacked", False) # was the static unpacking successful?
        packing_procedure = data.get("packing_procedure", "")
        unpacked_file_path = data.get("unpacked_file_path", "")

        return APKInsightResults(
            is_packed=is_packed,
            unpacked=unpacked,
            packing_procedure=packing_procedure,
            unpacked_file_path=unpacked_file_path
        )
    except Exception as e:
        print(f"Error parsing APKInsight results: {e}")
        return APKInsightResults(is_packed=False,unpacked=False, packing_procedure=str(e), unpacked_file_path="")


def _analyze_apk_with_apkInsight(apk_path: str, output_dir: str) -> json:
    """
    Analyze an APK file using APKInsight and populate an APKInsightResults object.
    Its main goal is to gain staticly insights into an APK. It is python3 fork of certain projects
    - apk-anal https://github.com/mhelwig/apk-anal
    - LoibRadar https://github.com/7homasSutter/LibRadar-Refactoring

    More at https://github.com/fkie-cad/APKInsight

    In future releases all the identified files which wouldn't be able to unpack staticly should be tracked in some manner using ammm

    Args:
        apk_path (str): Path to the APK file.
        output_dir (str): Path where the unpacked file should be written to.

    Returns:
        json: The raw json output from the APKInsight results.
    """
    try:
        

        k = APKInsight(apk_path=apk_path)
        result = {
            "is_packed": k.is_packed(),
            "unpacked": False,
            "packing_procedure": None,
            "unpacked_file_path": None
        }

        if result["is_packed"]:
            for plugin_result in k.get_plugin_results():
                if plugin_result["status"] == "success":
                    result["unpacked"] = True
                    result["packing_procedure"] = plugin_result["name"]
                    result["unpacked_file_path"] = plugin_result["output_file"]
                    break

        return json.dumps(result, indent=4)  # Pretty print the JSON result

    except Exception as e:
        print(f"Error analyzing APK with APKInsight: {e}")
        return APKInsightResults(apk_path=apk_path, raw_output=str(e))


def get_APKInsight_results(apk_path: str, output_dir: str | None = None) -> APKInsightResults:
    apkInsight_json = _analyze_apk_with_apkInsight(apk_path, output_dir)
    return _parse_apkInsights_results(apkInsight_json)