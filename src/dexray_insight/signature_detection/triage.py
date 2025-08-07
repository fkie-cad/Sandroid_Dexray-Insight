#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
from ..core.configuration import Configuration


# infos https://tria.ge/docs/cloud-api/submit/#submitting-samples

def triage_hashcheck(hash_value, config=None):
    if config is None:
        config = Configuration()
    
    # Handle both Configuration objects and dictionaries
    if hasattr(config, 'get_module_config'):
        # New Configuration object
        triage_config = config.get_module_config('signature_detection').get('providers', {}).get('triage', {})
        api_key = triage_config.get('api_key')
        enabled = triage_config.get('enabled', True)
    else:
        # Legacy dictionary config or fallback
        config = Configuration()
        triage_config = config.get_module_config('signature_detection').get('providers', {}).get('triage', {})
        api_key = triage_config.get('api_key')
        enabled = triage_config.get('enabled', True)
    
    # Check if provider is disabled or using placeholder API key
    if not enabled or not api_key or api_key == "YOUR_TRIAGE_API_KEY":
        if api_key == "YOUR_TRIAGE_API_KEY":
            logging.debug("Triage API key is using placeholder value, skipping")
        elif not enabled:
            logging.debug("Triage provider is disabled, skipping")
        else:
            logging.debug("Triage API key not configured, skipping")
        return None
    
    url = f'https://tria.ge/api/v0/{hash_value}'

    headers = {
        'Authorization': f'Bearer {api_key}'
    }

    respose = requests.get(url, headers = headers)
    json_response = respose.json()

    if respose.status_code == 200:
        logging.debug(f"Triage response: {json_response}")
        return json_response
    else:
        logging.debug("triage hashcheck failed")
        logging.debug(json_response)
        return None
