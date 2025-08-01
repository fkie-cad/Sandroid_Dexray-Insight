#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

import subprocess
import json
from .results.apkidResults import ApkidResults, ApkidFileAnalysis

def _parse_apkid_results(raw_json: str) -> ApkidResults:
    """
    Parse apkid JSON output into an ApkidResults object.

    Args:
        raw_json (str): The JSON output from apkid as a string.
        raw_output (str): The raw text output from apkid.

    Returns:
        ApkidResults: A populated ApkidResults object.
    """
    try:
        data = json.loads(raw_json)

        apkid_version = data.get("apkid_version", "")
        rules_sha256 = data.get("rules_sha256", "")
        files = [
            ApkidFileAnalysis(
                filename=file["filename"],
                matches=file.get("matches", {})
            )
            for file in data.get("files", [])
        ]

        return ApkidResults(
            apkid_version=apkid_version,
            files=files,
            rules_sha256=rules_sha256,
            raw_output=raw_json
        )
    except Exception as e:
        print(f"Error parsing apkid results: {e}")
        return ApkidResults(apkid_version="", raw_output=str(e))


def _analyze_apk_with_apkid(apk_path: str) -> json:
    """
    Analyze an APK file using apkid and populate an ApkidResults object.

    Args:
        apk_path (str): Path to the APK file.

    Returns:
        json: The raw json output from the apkid results.
    """
    try:
        # Run apkid command
        result = subprocess.run(
            ["apkid","--include-types","-j", apk_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Ensure the command executed successfully
        if result.returncode != 0:
            raise Exception(f"apkid failed: {result.stderr}")
        
        raw_output = result.stdout

        return raw_output

    except Exception as e:
        print(f"Error analyzing APK with apkid: {e}")
        return f'{{"error": "{str(e)}"}}'



def get_apkid_results(apk_path: str) -> ApkidResults:
    apkid_json = _analyze_apk_with_apkid(apk_path)
    return _parse_apkid_results(apkid_json)