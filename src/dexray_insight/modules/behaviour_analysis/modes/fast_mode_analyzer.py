#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fast Mode Analyzer

Provides basic behavior analysis using only APK object data,
without requiring full DEX analysis. Suitable for quick scans.
"""

import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class FastModeAnalyzer:
    """Basic analyzer for fast mode analysis using only APK object"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_basic_permissions(self, apk_obj, result) -> List[BehaviorEvidence]:
        """Fast mode: Basic permission analysis using only APK object"""
        evidence = []
        
        try:
            permissions = apk_obj.get_permissions()
            
            # Check for privacy-sensitive permissions
            sensitive_perms = [
                'android.permission.READ_PHONE_STATE',
                'android.permission.ACCESS_FINE_LOCATION', 
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.READ_CONTACTS',
                'android.permission.READ_SMS',
                'android.permission.READ_CALENDAR'
            ]
            
            detected_perms = [perm for perm in sensitive_perms if perm in permissions]
            
            for perm in detected_perms:
                evidence.append(BehaviorEvidence(
                    type='permission',
                    content=perm,
                    location='AndroidManifest.xml'
                ))
            
            result.add_finding(
                "sensitive_permissions",
                len(detected_perms) > 0,
                [ev.to_dict() for ev in evidence],
                f"Application requests {len(detected_perms)} privacy-sensitive permissions"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.debug(f"Error in basic permission analysis: {e}")
            return []
    
    def analyze_basic_components(self, apk_obj, result) -> List[BehaviorEvidence]:
        """Fast mode: Basic component analysis using only APK object"""
        evidence = []
        
        try:
            # Check for exported components
            activities = apk_obj.get_activities()
            services = apk_obj.get_services()
            receivers = apk_obj.get_receivers()
            
            exported_activities = []
            exported_services = []
            exported_receivers = []
            
            # Check activities
            for activity in activities:
                try:
                    if apk_obj.get_element('activity', 'android:name', activity) and \
                       apk_obj.get_element('activity', 'android:exported', activity) == 'true':
                        exported_activities.append(activity)
                        evidence.append(BehaviorEvidence(
                            type='activity',
                            content=activity,
                            location='AndroidManifest.xml'
                        ))
                except Exception:
                    continue
            
            # Check services
            for service in services:
                try:
                    if apk_obj.get_element('service', 'android:name', service) and \
                       apk_obj.get_element('service', 'android:exported', service) == 'true':
                        exported_services.append(service)
                        evidence.append(BehaviorEvidence(
                            type='service',
                            content=service,
                            location='AndroidManifest.xml'
                        ))
                except Exception:
                    continue
                    
            # Check receivers
            for receiver in receivers:
                try:
                    if apk_obj.get_element('receiver', 'android:name', receiver) and \
                       apk_obj.get_element('receiver', 'android:exported', receiver) == 'true':
                        exported_receivers.append(receiver)
                        evidence.append(BehaviorEvidence(
                            type='receiver',
                            content=receiver,
                            location='AndroidManifest.xml'
                        ))
                except Exception:
                    continue
            
            total_exported = len(exported_activities) + len(exported_services) + len(exported_receivers)
            
            # Limit evidence to first 5 entries of each type to avoid overwhelming output
            limited_evidence = []
            if evidence:
                activity_evidence = [ev for ev in evidence if ev.type == 'activity'][:5]
                service_evidence = [ev for ev in evidence if ev.type == 'service'][:5]  
                receiver_evidence = [ev for ev in evidence if ev.type == 'receiver'][:5]
                limited_evidence = activity_evidence + service_evidence + receiver_evidence
            
            result.add_finding(
                "exported_components",
                total_exported > 0,
                [ev.to_dict() for ev in limited_evidence],
                f"Application has {total_exported} exported components that may be accessible to other apps"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.debug(f"Error in basic component analysis: {e}")
            return []
    
    def analyze_app_metadata(self, apk_obj, result) -> List[BehaviorEvidence]:
        """Fast mode: Basic app metadata analysis"""
        evidence = []
        
        try:
            # Get basic app information
            package_name = apk_obj.get_package()
            app_name = apk_obj.get_app_name()
            target_sdk = apk_obj.get_target_sdk_version()
            min_sdk = apk_obj.get_min_sdk_version()
            
            # Store metadata for potential future use
            _ = {
                'package_name': package_name,
                'app_name': app_name,
                'target_sdk': target_sdk,
                'min_sdk': min_sdk
            }
            
            # Check for potentially suspicious metadata
            suspicious_indicators = []
            
            # Check for very low target SDK (potential security issue)
            if target_sdk and int(target_sdk) < 23:  # Android 6.0
                suspicious_indicators.append(f"Low target SDK version: {target_sdk}")
                evidence.append(BehaviorEvidence(
                    type='metadata',
                    content=f"target_sdk={target_sdk}",
                    location='AndroidManifest.xml',
                    pattern_matched='low_target_sdk'
                ))
            
            # Check for generic/suspicious package names
            if package_name:
                generic_patterns = ['com.example', 'com.test', 'test.']
                for pattern in generic_patterns:
                    if pattern in package_name.lower():
                        suspicious_indicators.append(f"Generic package name pattern: {pattern}")
                        evidence.append(BehaviorEvidence(
                            type='metadata',
                            content=package_name,
                            location='AndroidManifest.xml',
                            pattern_matched=f'generic_package_{pattern}'
                        ))
            
            result.add_finding(
                "app_metadata_analysis",
                len(suspicious_indicators) > 0,
                [ev.to_dict() for ev in evidence],
                f"Application metadata analysis found {len(suspicious_indicators)} potential issues"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.debug(f"Error in app metadata analysis: {e}")
            return []