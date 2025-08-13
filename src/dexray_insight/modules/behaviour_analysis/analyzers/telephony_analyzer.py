#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telephony Analyzer

Detects when applications attempt to access telephony-related information
such as IMEI, phone numbers, and SIM card details.
"""

import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class TelephonyAnalyzer:
    """Analyzer for telephony-related privacy behaviors"""
    
    IMEI_PATTERNS = [
        r'getDeviceId\(\)',
        r'TelephonyManager.*getDeviceId',
        r'READ_PHONE_STATE',
        r'getImei\(\)',
        r'getSubscriberId\(\)',
        r'android\.permission\.READ_PHONE_STATE'
    ]
    
    PHONE_NUMBER_PATTERNS = [
        r'getLine1Number\(\)',
        r'TelephonyManager.*getLine1Number',
        r'getSimSerialNumber\(\)',
        r'getSubscriberId\(\)',
        r'READ_PHONE_NUMBERS'
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_imei_access(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app tries to access IMEI"""
        evidence = []
        
        try:
            # Check permissions
            permissions = apk_obj.get_permissions()
            if 'android.permission.READ_PHONE_STATE' in permissions:
                evidence.append(BehaviorEvidence(
                    type='permission',
                    content='android.permission.READ_PHONE_STATE',
                    location='AndroidManifest.xml'
                ))
            
            # Search in strings and code
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            pattern_evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.IMEI_PATTERNS, "IMEI access"
            )
            evidence.extend(pattern_evidence)
            
            result.add_finding(
                "imei_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application attempts to access device IMEI"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"IMEI analysis failed: {e}")
            return []
    
    def analyze_phone_number_access(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app tries to get phone number"""
        evidence = []
        
        try:
            # Check permissions
            permissions = apk_obj.get_permissions()
            phone_permissions = [
                'android.permission.READ_PHONE_STATE',
                'android.permission.READ_PHONE_NUMBERS',
                'android.permission.READ_SMS'
            ]
            
            for perm in phone_permissions:
                if perm in permissions:
                    evidence.append(BehaviorEvidence(
                        type='permission',
                        content=perm,
                        location='AndroidManifest.xml'
                    ))
            
            # Search in strings and code
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            pattern_evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.PHONE_NUMBER_PATTERNS, "phone number access"
            )
            evidence.extend(pattern_evidence)
            
            result.add_finding(
                "phone_number_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application attempts to access phone number"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Phone number analysis failed: {e}")
            return []