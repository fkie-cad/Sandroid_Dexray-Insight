#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Triage API integration for malware analysis and detection."""

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

# infos https://tria.ge/docs/cloud-api/submit/#submitting-samples


def triage_hashcheck(hash_value, config=None):
    """Check hash against Triage malware analysis sandbox."""
    if config is None:
        config = Configuration()

    # Handle both Configuration objects and dictionaries
    if hasattr(config, "get_module_config"):
        # New Configuration object
        triage_config = config.get_module_config("signature_detection").get("providers", {}).get("triage", {})
        api_key = triage_config.get("api_key")
        enabled = triage_config.get("enabled", True)
    else:
        # Legacy dictionary config or fallback
        config = Configuration()
        triage_config = config.get_module_config("signature_detection").get("providers", {}).get("triage", {})
        api_key = triage_config.get("api_key")
        enabled = triage_config.get("enabled", True)

    # Check if provider is disabled or using placeholder API key
    if not enabled or not api_key or api_key == "YOUR_TRIAGE_API_KEY":  # pragma: allowlist secret
        if api_key == "YOUR_TRIAGE_API_KEY":  # pragma: allowlist secret
            logging.debug("Triage API key is using placeholder value, skipping")
        elif not enabled:
            logging.debug("Triage provider is disabled, skipping")
        else:
            logging.debug("Triage API key not configured, skipping")
        return None

    url = f"https://tria.ge/api/v0/{hash_value}"

    headers = {"Authorization": f"Bearer {api_key}"}

    respose = requests.get(url, headers=headers)
    json_response = respose.json()

    if respose.status_code == 200:
        logging.debug(f"Triage response: {json_response}")
        return json_response
    else:
        logging.debug("triage hashcheck failed")
        logging.debug(json_response)
        return None
