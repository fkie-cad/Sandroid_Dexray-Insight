#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

from androguard.misc import AnalyzeAPK
import logging
from loguru import logger

class Androguard_Obj:
    def __init__(self, apk_path):
        logging.getLogger("androguard").disabled = True

        # just suppresing the messages from androguard
        logger.remove()
        #logger.add(sys.stderr, level="WARNING")

        # Analyze the APK
        apk, dex_obj, dx_analysis = AnalyzeAPK(apk_path)
        
        self.androguard_apk = apk 
        self.androguard_dex = dex_obj
        self.androguard_analysisObj = dx_analysis

    # Getter for androguard_apk
    def get_androguard_apk(self):
        return self.androguard_apk

    # Getter for androguard_dex
    def get_androguard_dex(self):
        return self.androguard_dex

    # Getter for androguard_analysisObj
    def get_androguard_analysisObj(self):
        return self.androguard_analysisObj


