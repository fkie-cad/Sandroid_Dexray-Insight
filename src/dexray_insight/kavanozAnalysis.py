#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

import json
from kavanoz.core import Kavanoz
import logging
from loguru import logger
from .results.kavanozResults import KavanozResults

def _parse_kavanoz_results(raw_json: str) -> KavanozResults:
    """
    Parse kavanoz JSON output into an KavanozResults object.

    Args:
        raw_json (str): The JSON output from kavanoz as a string.
        raw_output (str): The raw text output from kavanoz.

    Returns:
        KavanozResults: A populated KavanozResults object.
    """
    try:
        data = json.loads(raw_json)

        is_packed = data.get("is_packed", False)
        unpacked = data.get("unpacked", False) # was the static unpacking successful?
        packing_procedure = data.get("packing_procedure", "")
        unpacked_file_path = data.get("unpacked_file_path", "")

        return KavanozResults(
            is_packed=is_packed,
            unpacked=unpacked,
            packing_procedure=packing_procedure,
            unpacked_file_path=unpacked_file_path
        )
    except Exception as e:
        print(f"Error parsing kavanoz results: {e}")
        return KavanozResults(is_packed=False,unpacked=False, packing_procedure=str(e), unpacked_file_path="")


def _analyze_apk_with_kavanoz(apk_path: str, output_dir: str) -> json:
    """
    Analyze an APK file using kavanoz and populate an KavanozResults object.
    Its main goal is to identify packed files inside the APK and than to unpacking them staticly

    In future releases all the identified files which wouldn't be able to unpack staticly should be tracked in some manner using ammm

    Args:
        apk_path (str): Path to the APK file.
        output_dir (str): Path where the unpacked file should be written to.

    Returns:
        json: The raw json output from the kavanoz results.
    """
    try:
        logging.getLogger("kavanoz").disabled = True
        logger.remove()

        k = Kavanoz(apk_path=apk_path, output_dir=output_dir)
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
        print(f"Error analyzing APK with kavanoz: {e}")
        return KavanozResults()


def get_kavanoz_results(apk_path: str, output_dir: str | None = None) -> KavanozResults:
    kavanoz_json = _analyze_apk_with_kavanoz(apk_path, output_dir)
    return _parse_kavanoz_results(kavanoz_json)