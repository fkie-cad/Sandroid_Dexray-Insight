#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseAnalysisModule, AnalysisContext, AnalysisStatus, register_module
from ..results.BehaviourAnalysisResults import BehaviourAnalysisResults

@register_module('behaviour_analysis')
class BehaviourAnalysisModule(BaseAnalysisModule):
    """Module for behavioral analysis of Android APK files with fast/deep modes"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
    
    def get_name(self) -> str:
        return "Behaviour Analysis"
    
    def get_description(self) -> str:
        return "Performs behavioral analysis to detect privacy-sensitive behaviors. Supports fast mode (APK only) and deep mode (full DEX analysis)"
    
    def get_dependencies(self) -> List[str]:
        return ["apk_overview"]  # Requires APK overview for basic analysis
    
    def get_priority(self) -> int:
        """Return lowest priority to ensure this runs last"""
        return 1000
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> BehaviourAnalysisResults:
        """
        Perform behavioral analysis in fast or deep mode
        
        Args:
            apk_path: Path to APK file
            context: Analysis context
            
        Returns:
            BehaviourAnalysisResults with behavioral findings
        """
        start_time = time.time()
        
        try:
            # Check if we're in deep mode
            # By default, run in fast mode. Deep mode is enabled via --deep flag or config
            deep_mode = self.config.get('deep_mode', False) or context.config.get('behaviour_analysis', {}).get('deep_mode', False)
            
            # Module should run by default in fast mode unless explicitly disabled
            module_enabled = context.config.get('behaviour_analysis', {}).get('enabled', True)
            if not module_enabled:
                return BehaviourAnalysisResults(
                    module_name="behaviour_analysis",
                    status=AnalysisStatus.SKIPPED,
                    error_message="Behaviour analysis module disabled in configuration",
                    execution_time=time.time() - start_time
                )
            
            if deep_mode:
                self.logger.info("Starting behaviour analysis in DEEP mode...")
            else:
                self.logger.info("Starting behaviour analysis in FAST mode...")
            
            # Validate that androguard object is available
            if not context.androguard_obj:
                return BehaviourAnalysisResults(
                    module_name="behaviour_analysis",
                    status=AnalysisStatus.FAILURE,
                    error_message="Androguard object not available in context",
                    execution_time=time.time() - start_time
                )
            
            # Get androguard objects based on mode
            apk_obj = context.androguard_obj.get_androguard_apk()
            
            # Only get DEX objects in deep mode
            if deep_mode:
                dex_obj = context.androguard_obj.get_androguard_dex()
                dx_obj = context.androguard_obj.get_androguard_analysisObj()
                # Store these globally for security analysis access
                context.deep_analysis_objects = {
                    'apk_obj': apk_obj,
                    'dex_obj': dex_obj,
                    'dx_obj': dx_obj
                }
            else:
                dex_obj = None
                dx_obj = None
                # Store only APK object in fast mode
                context.fast_analysis_objects = {
                    'apk_obj': apk_obj
                }
            
            result = BehaviourAnalysisResults(
                module_name="behaviour_analysis",
                status=AnalysisStatus.SUCCESS,
                execution_time=0.0
            )
            
            # Store androguard objects in the result for security analysis access
            if deep_mode:
                result.androguard_objects = {
                    'mode': 'deep',
                    'apk_obj': apk_obj,
                    'dex_obj': dex_obj,
                    'dx_obj': dx_obj
                }
            else:
                result.androguard_objects = {
                    'mode': 'fast',
                    'apk_obj': apk_obj,
                    'dex_obj': None,
                    'dx_obj': None
                }
            
            # Analyze each feature based on mode
            if deep_mode:
                # Full analysis with DEX objects
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
            else:
                # Fast mode - only basic APK analysis
                self._analyze_basic_permissions(apk_obj, result)
                self._analyze_basic_components(apk_obj, result)
            
            # Generate summary
            detected_count = len(result.get_detected_features())
            total_count = len(result.findings)
            result.summary = {
                'total_features_analyzed': total_count,
                'features_detected': detected_count,
                'detection_rate': round(detected_count / total_count * 100, 2) if total_count > 0 else 0
            }
            
            result.execution_time = time.time() - start_time
            mode_str = "DEEP" if deep_mode else "FAST"
            self.logger.info(f"Behaviour analysis ({mode_str} mode) completed in {result.execution_time:.2f}s - {detected_count}/{total_count} behaviors detected")
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Behaviour analysis failed: {str(e)}")
            
            return BehaviourAnalysisResults(
                module_name="behaviour_analysis",
                status=AnalysisStatus.FAILURE,
                error_message=str(e),
                execution_time=execution_time
            )
    
    def _analyze_device_model_access(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_imei_access(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_android_version_access(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_phone_number_access(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_clipboard_usage(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_dynamic_receivers(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_camera_access(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_running_services_access(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_installed_applications(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_installed_packages(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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
    
    def _analyze_reflection_usage(self, apk_obj, dex_obj, dx_obj, result: BehaviourAnalysisResults):
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

    def _analyze_basic_permissions(self, apk_obj, result: BehaviourAnalysisResults):
        """Fast mode: Basic permission analysis using only APK object"""
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
            
            result.add_finding(
                "sensitive_permissions",
                len(detected_perms) > 0,
                [{'type': 'permission', 'content': perm} for perm in detected_perms],
                f"Application requests {len(detected_perms)} privacy-sensitive permissions"
            )
            
        except Exception as e:
            self.logger.debug(f"Error in basic permission analysis: {e}")

    def _analyze_basic_components(self, apk_obj, result: BehaviourAnalysisResults):
        """Fast mode: Basic component analysis using only APK object"""
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
                except Exception:
                    continue
            
            # Check services
            for service in services:
                try:
                    if apk_obj.get_element('service', 'android:name', service) and \
                       apk_obj.get_element('service', 'android:exported', service) == 'true':
                        exported_services.append(service)
                except Exception:
                    continue
                    
            # Check receivers
            for receiver in receivers:
                try:
                    if apk_obj.get_element('receiver', 'android:name', receiver) and \
                       apk_obj.get_element('receiver', 'android:exported', receiver) == 'true':
                        exported_receivers.append(receiver)
                except Exception:
                    continue
            
            total_exported = len(exported_activities) + len(exported_services) + len(exported_receivers)
            evidence = []
            
            if exported_activities:
                evidence.extend([{'type': 'activity', 'content': act} for act in exported_activities[:5]])
            if exported_services:
                evidence.extend([{'type': 'service', 'content': svc} for svc in exported_services[:5]])
            if exported_receivers:
                evidence.extend([{'type': 'receiver', 'content': rec} for rec in exported_receivers[:5]])
            
            result.add_finding(
                "exported_components",
                total_exported > 0,
                evidence,
                f"Application has {total_exported} exported components that may be accessible to other apps"
            )
            
        except Exception as e:
            self.logger.debug(f"Error in basic component analysis: {e}")