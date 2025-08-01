#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

from .hash import get_sha256_hash_of_apk
from .koodous import koodous_hash_check
from .vt import vt_check_file_reputation
from .triage import triage_hashcheck
from ..core.configuration import Configuration
import logging



def signature_detection_execute(apk_path, androguard_obj, config=None):
    if config is None:
        config = Configuration()
        
    try:
        logging.debug("Signature detection module running")
        responses = {} # a dict with different results 
        apk_hash = get_sha256_hash_of_apk(apk_path)
        # apk_hash = "3d3aa166f7b86379e970a7e583d1a6b22ea9f3217a516fe65345d23055f13723" # test apk hash
        logging.info(f"SHA256 of {apk_path}: {apk_hash}")
        logging.info("running koodous signature check")
        responses['koodous'] = koodous_hash_check(apk_hash, config)
        logging.info("running VirusTotal signature check")
        responses['vt'] = vt_check_file_reputation(apk_hash, config)
        logging.info("running triage signature check")
        triage_result = triage_hashcheck(apk_hash, config)
        responses['triage'] = triage_result if triage_result is not None else "No results"

        #logging.debug(f"Responses dict: {responses}")
    except Exception as exception_info:
        logging.error(f"Error in signature detection: {exception_info}")
        logging.debug(f"Signature detection error details: {exception_info}", exc_info=True)

    return responses
