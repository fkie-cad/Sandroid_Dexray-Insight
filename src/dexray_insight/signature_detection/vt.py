#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
from datetime import datetime
from ..core.configuration import Configuration

def vt_check_file_reputation(hash_value, config=None):
    if config is None:
        config = Configuration()
    
    # Handle both Configuration objects and dictionaries
    if hasattr(config, 'get_module_config'):
        # New Configuration object
        vt_config = config.get_module_config('signature_detection').get('providers', {}).get('virustotal', {})
        api_key = vt_config.get('api_key')
        enabled = vt_config.get('enabled', True)
    else:
        # Legacy dictionary config or fallback
        config = Configuration()
        vt_config = config.get_module_config('signature_detection').get('providers', {}).get('virustotal', {})
        api_key = vt_config.get('api_key')
        enabled = vt_config.get('enabled', True)
    
    # Check if provider is disabled or using placeholder API key
    if not enabled or not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY":
        if api_key == "YOUR_VIRUSTOTAL_API_KEY":
            logging.debug("VirusTotal API key is using placeholder value, skipping")
        elif not enabled:
            logging.debug("VirusTotal provider is disabled, skipping")
        else:
            logging.debug("VirusTotal API key not configured, skipping")
        return None
    
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': api_key
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()

        links_value = json_response['data']['links']['self']
        last_submission_date = json_response['data']['attributes']['last_submission_date']
        last_analysis_results = json_response['data']['attributes']['last_analysis_results']


        # Extract hashes
        sha1_hash = json_response['data']['attributes'].get('sha1', 'N/A')
        sha256_hash = json_response['data']['attributes'].get('sha256', 'N/A')
        md5_hash = json_response['data']['attributes'].get('md5', 'N/A')
        ssdeep_hash = json_response['data']['attributes'].get('ssdeep', 'N/A')


        # Initialize counters
        none_result_count = 0
        non_none_result_count = 0

        # Iterate through each engine's result in "last_analysis_results"
        for engine_details in last_analysis_results.values():
            if engine_details['result'] is None:
                none_result_count += 1
            else:
                non_none_result_count += 1

        # Total number of items is simply the length of "last_analysis_results"
        total_items = len(last_analysis_results)

        # Convert Unix timestamp to datetime object to get "YYYY-MM-DD HH:MM:SS" format
        dt_object = datetime.utcfromtimestamp(last_submission_date)
        last_submission_data_readable = dt_object.strftime('%Y-%m-%d %H:%M:%S')

        # Creating a result dictionary
        result_dict = {
                "vt": {
                    "url": links_value,
                    "hash": {
                        "md5": md5_hash,
                        "ssdeep": ssdeep_hash,
                        "sha1": sha1_hash,
                        "sha256:": sha256_hash
                    },
                    "detection": {
                        "last": last_submission_data_readable,
                        "score": str(non_none_result_count)+ "/"+ str(total_items),
                        "total": total_items,
                        "undetected": none_result_count,
                        "detected": non_none_result_count
                    }
                    
                    }
        }



        # Print the full response to explore the structure or adjust to print specific details
        logging.debug(f"APK Information: {result_dict}")
        return result_dict
    elif response.status_code == 404:
        logging.info("No public analysis available")
        return None
    else:
        logging.error(f"Error: {response.status_code}")
        return None
