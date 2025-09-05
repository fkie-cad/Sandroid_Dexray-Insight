#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Koodous API integration for Android malware detection."""

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

import requests

from ..core.configuration import Configuration


def koodous_hash_check(apk_hash, config=None):
    """Check APK hash against Koodous threat intelligence database."""
    if config is None:
        config = Configuration()

    # Handle both Configuration objects and dictionaries
    if hasattr(config, "get_module_config"):
        # New Configuration object
        koodous_config = config.get_module_config("signature_detection").get("providers", {}).get("koodous", {})
        api_token = koodous_config.get("api_key")
        enabled = koodous_config.get("enabled", True)
    else:
        # Legacy dictionary config or fallback
        config = Configuration()
        koodous_config = config.get_module_config("signature_detection").get("providers", {}).get("koodous", {})
        api_token = koodous_config.get("api_key")
        enabled = koodous_config.get("enabled", True)

    # Check if provider is disabled or using placeholder API key
    if not enabled or not api_token or api_token == "YOUR_KOODOUS_API_KEY":
        if api_token == "YOUR_KOODOUS_API_KEY":
            logging.debug("Koodous API key is using placeholder value, skipping")
        elif not enabled:
            logging.debug("Koodous provider is disabled, skipping")
        else:
            logging.debug("Koodous API key not configured, skipping")
        return None

    headers = {
        "Authorization": f"Token {api_token}",
    }

    logging.debug(f"sending request to koodous: https://api.koodous.com/apks/{apk_hash}")
    response = requests.get(f"https://developer.koodous.com/apks/{apk_hash}", headers=headers)

    if response.status_code == 200:
        json_response = response.json()

        url = json_response.get("url", "N/A")
        sha256 = json_response.get("sha256", "N/A")
        md5 = json_response.get("md5", "N/A")
        updated_at = json_response.get("updated_at", "N/A")

        # Creating a result dictionary
        result_dict = {
            "koodous": {
                "url": url,
                "last": updated_at,
                "hash": {"md5": md5, "sha256:": sha256},
            }
        }

        logging.debug(f"APK Information: {result_dict}")
        return result_dict
    elif response.status_code == 404:
        logging.info("No public analysis available")
        return None
    else:
        logging.error(f"Failed to retrieve APK information. Status code: {response.status_code}")
        logging.debug(f"Failed to retrieve APK information. Status code: {response.text}")
        return None
