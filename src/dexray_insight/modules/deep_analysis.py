#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from ..core.base_classes import BaseAnalysisModule, AnalysisContext, AnalysisStatus, register_module
from ..results.DeepAnalysisResults import DeepAnalysisResults, DeepAnalysisFinding

@register_module('deep_analysis')
class DeepAnalysisModule(BaseAnalysisModule):
    """Module for deep behavioral analysis of Android APK files"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
    
    def get_name(self) -> str:
        return "Deep Analysis"
    
    def get_description(self) -> str:
        return "Performs deep behavioral analysis to detect privacy-sensitive behaviors and advanced techniques"
    
    def get_dependencies(self) -> List[str]:
        return ["apk_overview"]  # Requires APK overview for basic analysis
    
    def get_priority(self) -> int:
        """Return lowest priority to ensure this runs last"""
        return 1000
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> DeepAnalysisResults:
        """
        Perform deep behavioral analysis
        
        Args:
            apk_path: Path to APK file
            context: Analysis context
            
        Returns:
            DeepAnalysisResults with behavioral findings
        """
        start_time = time.time()
        
        try:
            self.logger.info("Starting deep analysis...")
            
            # Validate that androguard object is available
            if not context.androguard_obj:
                return DeepAnalysisResults(
                    module_name="deep_analysis",
                    status=AnalysisStatus.FAILURE,
                    error_message="Androguard object not available in context",
                    execution_time=time.time() - start_time
                )
            
            # Get androguard objects
            apk_obj = context.androguard_obj.get_androguard_apk()
            dex_obj = context.androguard_obj.get_androguard_dex()
            dx_obj = context.androguard_obj.get_androguard_analysisObj()
            
            result = DeepAnalysisResults(
                module_name="deep_analysis",
                status=AnalysisStatus.SUCCESS,
                execution_time=0.0
            )
            
            # Analyze each feature
            self._analyze_device_model_access(apk_obj, dex_obj, dx_obj, result)
            self._analyze_imei_access(apk_obj, dex_obj, dx_obj, result)
            self._analyze_android_version_access(apk_obj, dex_obj, dx_obj, result)
            self._analyze_phone_number_access(apk_obj, dex_obj, dx_obj, result)
            self._analyze_clipboard_usage(apk_obj, dex_obj, dx_obj, result)
            self._analyze_dynamic_receivers(apk_obj, dex_obj, dx_obj, result)
            self._analyze_camera_access(apk_obj, dex_obj, dx_obj, result)
            self._analyze_running_services_access(apk_obj, dex_obj, dx_obj, result)
            self._analyze_installed_applications(apk_obj, dex_obj, dx_obj, result)
            self._analyze_installed_packages(apk_obj, dex_obj, dx_obj, result)
            self._analyze_reflection_usage(apk_obj, dex_obj, dx_obj, result)
            
            # Generate summary
            detected_count = len(result.get_detected_features())
            total_count = len(result.findings)
            result.summary = {
                'total_features_analyzed': total_count,
                'features_detected': detected_count,
                'detection_rate': round(detected_count / total_count * 100, 2) if total_count > 0 else 0
            }
            
            result.execution_time = time.time() - start_time
            self.logger.info(f"Deep analysis completed in {result.execution_time:.2f}s - {detected_count}/{total_count} behaviors detected")
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Deep analysis failed: {str(e)}")
            
            return DeepAnalysisResults(
                module_name="deep_analysis",
                status=AnalysisStatus.FAILURE,
                error_message=str(e),
                execution_time=execution_time
            )
    
    def _analyze_device_model_access(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app accesses device model information"""
        evidence = []
        patterns = [
            r'android\.os\.Build\.MODEL',
            r'Build\.MODEL',
            r'getSystemService.*DEVICE_POLICY_SERVICE',
            r'getModel\(\)',
            r'android\.provider\.Settings\.Secure\.ANDROID_ID'
        ]
        
        # Search in DEX strings
        if dex_obj:
            for i, dex in enumerate(dex_obj):
                try:
                    dex_strings = dex.get_strings()
                    for string in dex_strings:
                        string_val = str(string)
                        for pattern in patterns:
                            if re.search(pattern, string_val, re.IGNORECASE):
                                evidence.append({
                                    'type': 'string',
                                    'content': string_val,
                                    'pattern_matched': pattern,
                                    'location': f'DEX {i+1} strings',
                                    'dex_index': i
                                })
                except Exception as e:
                    self.logger.debug(f"Error analyzing device model access in DEX {i}: {e}")
        
        # Search in smali code
        if dex_obj:
            for i, dex in enumerate(dex_obj):
                try:
                    for cls in dex.get_classes():
                        class_source = cls.get_source()
                        if class_source:
                            for pattern in patterns:
                                matches = re.finditer(pattern, class_source, re.IGNORECASE)
                                for match in matches:
                                    # Get line number context
                                    lines = class_source[:match.start()].count('\n')
                                    evidence.append({
                                        'type': 'code',
                                        'content': match.group(),
                                        'pattern_matched': pattern,
                                        'class_name': cls.get_name(),
                                        'line_number': lines + 1,
                                        'dex_index': i
                                    })
                except Exception as e:
                    self.logger.debug(f"Error analyzing device model access in smali DEX {i}: {e}")
        
        result.add_finding(
            "device_model_access",
            len(evidence) > 0,
            evidence,
            "Application attempts to access device model information"
        )
    
    def _analyze_imei_access(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app tries to access IMEI"""
        evidence = []
        patterns = [
            r'getDeviceId\(\)',
            r'TelephonyManager.*getDeviceId',
            r'READ_PHONE_STATE',
            r'getImei\(\)',
            r'getSubscriberId\(\)',
            r'android\.permission\.READ_PHONE_STATE'
        ]
        
        # Check permissions
        permissions = apk_obj.get_permissions()
        if 'android.permission.READ_PHONE_STATE' in permissions:
            evidence.append({
                'type': 'permission',
                'content': 'android.permission.READ_PHONE_STATE',
                'location': 'AndroidManifest.xml'
            })
        
        # Search in strings and code
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "IMEI access")
        
        result.add_finding(
            "imei_access",
            len(evidence) > 0,
            evidence,
            "Application attempts to access device IMEI"
        )
    
    def _analyze_android_version_access(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app accesses Android version information"""
        evidence = []
        patterns = [
            r'android\.os\.Build\.VERSION',
            r'Build\.VERSION',
            r'SDK_INT',
            r'RELEASE',
            r'getSystemProperty.*version'
        ]
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "Android version access")
        
        result.add_finding(
            "android_version_access",
            len(evidence) > 0,
            evidence,
            "Application accesses Android version information"
        )
    
    def _analyze_phone_number_access(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app tries to get phone number"""
        evidence = []
        patterns = [
            r'getLine1Number\(\)',
            r'TelephonyManager.*getLine1Number',
            r'getSimSerialNumber\(\)',
            r'getSubscriberId\(\)',
            r'READ_PHONE_NUMBERS'
        ]
        
        # Check permissions
        permissions = apk_obj.get_permissions()
        phone_permissions = [
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.READ_SMS'
        ]
        
        for perm in phone_permissions:
            if perm in permissions:
                evidence.append({
                    'type': 'permission',
                    'content': perm,
                    'location': 'AndroidManifest.xml'
                })
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "phone number access")
        
        result.add_finding(
            "phone_number_access",
            len(evidence) > 0,
            evidence,
            "Application attempts to access phone number"
        )
    
    def _analyze_clipboard_usage(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app uses clipboard"""
        evidence = []
        patterns = [
            r'ClipboardManager',
            r'getSystemService.*CLIPBOARD_SERVICE',
            r'getPrimaryClip\(\)',
            r'setPrimaryClip\(\)',
            r'android\.content\.ClipboardManager'
        ]
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "clipboard usage")
        
        result.add_finding(
            "clipboard_usage",
            len(evidence) > 0,
            evidence,
            "Application uses clipboard functionality"
        )
    
    def _analyze_dynamic_receivers(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check for dynamically registered broadcast receivers"""
        evidence = []
        patterns = [
            r'registerReceiver\(',
            r'unregisterReceiver\(',
            r'BroadcastReceiver',
            r'IntentFilter.*addAction'
        ]
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "dynamic broadcast receivers")
        
        result.add_finding(
            "dynamic_receivers",
            len(evidence) > 0,
            evidence,
            "Application registers broadcast receivers dynamically"
        )
    
    def _analyze_camera_access(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app tries to access camera"""
        evidence = []
        patterns = [
            r'Camera\.open\(',
            r'camera2\.CameraManager',
            r'SurfaceView',
            r'MediaRecorder',
            r'CAMERA'
        ]
        
        # Check permissions
        permissions = apk_obj.get_permissions()
        camera_permissions = [
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO'
        ]
        
        for perm in camera_permissions:
            if perm in permissions:
                evidence.append({
                    'type': 'permission',
                    'content': perm,
                    'location': 'AndroidManifest.xml'
                })
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "camera access")
        
        result.add_finding(
            "camera_access",
            len(evidence) > 0,
            evidence,
            "Application attempts to access camera"
        )
    
    def _analyze_running_services_access(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app tries to get running services"""
        evidence = []
        patterns = [
            r'getRunningServices\(',
            r'ActivityManager.*getRunningServices',
            r'getRunningAppProcesses\(',
            r'getRunningTasks\(',
            r'ProcessInfo'
        ]
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "running services access")
        
        result.add_finding(
            "running_services_access",
            len(evidence) > 0,
            evidence,
            "Application tries to access running services information"
        )
    
    def _analyze_installed_applications(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app gets installed applications"""
        evidence = []
        patterns = [
            r'getInstalledApplications\(',
            r'PackageManager.*getInstalledApplications',
            r'ApplicationInfo',
            r'queryIntentActivities\(',
            r'QUERY_ALL_PACKAGES'
        ]
        
        # Check permissions
        permissions = apk_obj.get_permissions()
        if 'android.permission.QUERY_ALL_PACKAGES' in permissions:
            evidence.append({
                'type': 'permission',
                'content': 'android.permission.QUERY_ALL_PACKAGES',
                'location': 'AndroidManifest.xml'
            })
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "installed applications access")
        
        result.add_finding(
            "installed_applications_access",
            len(evidence) > 0,
            evidence,
            "Application accesses installed applications list"
        )
    
    def _analyze_installed_packages(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app gets installed packages"""
        evidence = []
        patterns = [
            r'getInstalledPackages\(',
            r'PackageManager.*getInstalledPackages',
            r'PackageInfo',
            r'getPackageInfo\(',
            r'GET_INSTALLED_PACKAGES'
        ]
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "installed packages access")
        
        result.add_finding(
            "installed_packages_access",
            len(evidence) > 0,
            evidence,
            "Application accesses installed packages information"
        )
    
    def _analyze_reflection_usage(self, apk_obj, dex_obj, dx_obj, result: DeepAnalysisResults):
        """Check if app uses reflection"""
        evidence = []
        patterns = [
            r'Class\.forName\(',
            r'getDeclaredMethod\(',
            r'getMethod\(',
            r'invoke\(',
            r'java\.lang\.reflect',
            r'Method\.invoke\(',
            r'getDeclaredField\(',
            r'getField\('
        ]
        
        self._search_patterns_in_apk(apk_obj, dex_obj, dx_obj, patterns, evidence, "reflection usage")
        
        result.add_finding(
            "reflection_usage",
            len(evidence) > 0,
            evidence,
            "Application uses Java reflection"
        )
    
    def _search_patterns_in_apk(self, apk_obj, dex_obj, dx_obj, patterns: List[str], evidence: List[Dict[str, Any]], feature_name: str):
        """Helper method to search patterns in APK strings and code"""
        
        # Search in DEX strings
        if dex_obj:
            for i, dex in enumerate(dex_obj):
                try:
                    dex_strings = dex.get_strings()
                    for string in dex_strings:
                        string_val = str(string)
                        for pattern in patterns:
                            if re.search(pattern, string_val, re.IGNORECASE):
                                evidence.append({
                                    'type': 'string',
                                    'content': string_val,
                                    'pattern_matched': pattern,
                                    'location': f'DEX {i+1} strings',
                                    'dex_index': i
                                })
                except Exception as e:
                    self.logger.debug(f"Error analyzing {feature_name} in DEX strings {i}: {e}")
        
        # Search in smali code
        if dex_obj:
            for i, dex in enumerate(dex_obj):
                try:
                    for cls in dex.get_classes():
                        class_source = cls.get_source()
                        if class_source:
                            for pattern in patterns:
                                matches = re.finditer(pattern, class_source, re.IGNORECASE)
                                for match in matches:
                                    # Get line number context
                                    lines = class_source[:match.start()].count('\n')
                                    evidence.append({
                                        'type': 'code',
                                        'content': match.group(),
                                        'pattern_matched': pattern,
                                        'class_name': cls.get_name(),
                                        'line_number': lines + 1,
                                        'dex_index': i
                                    })
                except Exception as e:
                    self.logger.debug(f"Error analyzing {feature_name} in smali DEX {i}: {e}")