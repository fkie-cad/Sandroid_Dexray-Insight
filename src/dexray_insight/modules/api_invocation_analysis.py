#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
from typing import List, Dict, Any
from dataclasses import dataclass

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module

@dataclass
class APIInvocationAnalysisResult(BaseResult):
    """Result class for API invocation analysis"""
    api_calls: List[Dict[str, Any]] = None
    reflection_usage: List[Dict[str, Any]] = None
    native_method_calls: List[str] = None
    suspicious_api_calls: List[Dict[str, Any]] = None
    total_api_calls: int = 0
    
    def __post_init__(self):
        if self.api_calls is None:
            self.api_calls = []
        if self.reflection_usage is None:
            self.reflection_usage = []
        if self.native_method_calls is None:
            self.native_method_calls = []
        if self.suspicious_api_calls is None:
            self.suspicious_api_calls = []
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'api_calls': self.api_calls,
            'reflection_usage': self.reflection_usage,
            'native_method_calls': self.native_method_calls,
            'suspicious_api_calls': self.suspicious_api_calls,
            'total_api_calls': self.total_api_calls,
            'analysis_summary': {
                'reflection_detected': len(self.reflection_usage) > 0,
                'native_methods_detected': len(self.native_method_calls) > 0,
                'suspicious_calls_found': len(self.suspicious_api_calls)
            }
        })
        return base_dict

@register_module('api_invocation')
class APIInvocationAnalysisModule(BaseAnalysisModule):
    """API invocation analysis module for detecting method calls and reflection usage"""
    
    # Suspicious API patterns that might indicate malicious behavior
    SUSPICIOUS_API_PATTERNS = [
        'java.lang.Runtime.exec',
        'java.lang.ProcessBuilder',
        'android.telephony.SmsManager',
        'android.location.LocationManager',
        'android.hardware.Camera',
        'android.media.AudioRecord',
        'java.net.HttpURLConnection',
        'javax.net.ssl',
        'java.security.MessageDigest',
        'javax.crypto',
        'android.app.admin.DevicePolicyManager',
        'android.content.pm.PackageManager.getInstalledPackages',
        'android.provider.Settings.Secure',
        'java.lang.reflect'
    ]
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.reflection_analysis = config.get('reflection_analysis', True)
        self.detect_native_calls = config.get('detect_native_calls', True)
        self.suspicious_api_detection = config.get('suspicious_api_detection', True)
    
    def get_dependencies(self) -> List[str]:
        """No dependencies for API invocation analysis"""
        return []
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> APIInvocationAnalysisResult:
        """
        Perform API invocation analysis on the APK
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            APIInvocationAnalysisResult with analysis results
        """
        start_time = time.time()
        
        try:
            if not context.androguard_obj:
                raise ValueError("Androguard object not available in context")
            
            # Get analysis objects
            dx = context.androguard_obj.get_androguard_analysisObj()
            
            api_calls = []
            reflection_usage = []
            native_method_calls = []
            suspicious_api_calls = []
            
            if dx:
                # Analyze method calls
                api_calls = self._analyze_method_calls(dx)
                
                # Analyze reflection usage if enabled
                if self.reflection_analysis:
                    reflection_usage = self._analyze_reflection_usage(dx)
                
                # Detect native method calls if enabled
                if self.detect_native_calls:
                    native_method_calls = self._detect_native_calls(dx)
                
                # Detect suspicious API calls if enabled
                if self.suspicious_api_detection:
                    suspicious_api_calls = self._detect_suspicious_api_calls(api_calls)
            
            execution_time = time.time() - start_time
            
            return APIInvocationAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                api_calls=api_calls,
                reflection_usage=reflection_usage,
                native_method_calls=native_method_calls,
                suspicious_api_calls=suspicious_api_calls,
                total_api_calls=len(api_calls)
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"API invocation analysis failed: {str(e)}")
            
            return APIInvocationAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                total_api_calls=0
            )
    
    def _analyze_method_calls(self, dx) -> List[Dict[str, Any]]:
        """Analyze method calls in the APK"""
        api_calls = []
        
        try:
            # This is a simplified implementation
            # In a full implementation, you would iterate through all methods
            # and extract their external API calls
            
            for method in dx.get_methods():
                try:
                    method_name = method.get_method().get_name()
                    class_name = method.get_method().get_class_name()
                    
                    # Skip if this is an internal method
                    if not class_name.startswith('L'):
                        continue
                    
                    # Get external method calls
                    for call in method.get_xref_to():
                        called_method = call[1]
                        called_class = called_method.get_method().get_class_name()
                        called_method_name = called_method.get_method().get_name()
                        
                        # Check if this is an external API call
                        if (called_class.startswith('Landroid/') or 
                            called_class.startswith('Ljava/') or
                            called_class.startswith('Ljavax/')):
                            
                            api_calls.append({
                                'caller_class': class_name,
                                'caller_method': method_name,
                                'called_class': called_class,
                                'called_method': called_method_name,
                                'api_type': self._classify_api_type(called_class)
                            })
                            
                except Exception as e:
                    self.logger.debug(f"Error analyzing method {method}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to analyze method calls: {str(e)}")
        
        return api_calls
    
    def _analyze_reflection_usage(self, dx) -> List[Dict[str, Any]]:
        """Analyze reflection usage in the APK"""
        reflection_usage = []
        
        try:
            # Look for common reflection patterns
            reflection_patterns = [
                'java.lang.Class.forName',
                'java.lang.reflect.Method.invoke',
                'java.lang.reflect.Field.get',
                'java.lang.reflect.Field.set',
                'java.lang.reflect.Constructor.newInstance'
            ]
            
            for method in dx.get_methods():
                try:
                    # Check for reflection API usage
                    for call in method.get_xref_to():
                        called_method = call[1]
                        full_method_name = f"{called_method.get_method().get_class_name()}.{called_method.get_method().get_name()}"
                        
                        for pattern in reflection_patterns:
                            if pattern in full_method_name:
                                reflection_usage.append({
                                    'caller_class': method.get_method().get_class_name(),
                                    'caller_method': method.get_method().get_name(),
                                    'reflection_api': pattern,
                                    'location': full_method_name
                                })
                                break
                
                except Exception as e:
                    self.logger.debug(f"Error analyzing reflection in method {method}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to analyze reflection usage: {str(e)}")
        
        return reflection_usage
    
    def _detect_native_calls(self, dx) -> List[str]:
        """Detect native method calls"""
        native_calls = []
        
        try:
            for method in dx.get_methods():
                try:
                    # Check if this is an external method (skip those)
                    method_obj = method.get_method()
                    if hasattr(method_obj, 'get_access_flags'):
                        if method_obj.get_access_flags() & 0x100:  # ACC_NATIVE flag
                            native_calls.append(f"{method_obj.get_class_name()}.{method_obj.get_name()}")
                    else:
                        # This is likely an external method, skip it
                        self.logger.debug(f"Skipping external method: {method}")
                
                except Exception as e:
                    self.logger.debug(f"Error checking native method {method}: {str(e)}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to detect native calls: {str(e)}")
        
        return native_calls
    
    def _detect_suspicious_api_calls(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect suspicious API calls that might indicate malicious behavior"""
        suspicious_calls = []
        
        for api_call in api_calls:
            full_api_name = f"{api_call['called_class']}.{api_call['called_method']}"
            
            for suspicious_pattern in self.SUSPICIOUS_API_PATTERNS:
                if suspicious_pattern in full_api_name:
                    suspicious_calls.append({
                        **api_call,
                        'suspicious_pattern': suspicious_pattern,
                        'risk_level': self._assess_risk_level(suspicious_pattern)
                    })
                    break
        
        return suspicious_calls
    
    def _classify_api_type(self, class_name: str) -> str:
        """Classify the type of API based on class name"""
        if class_name.startswith('Landroid/'):
            if 'telephony' in class_name:
                return 'telephony'
            elif 'location' in class_name:
                return 'location'
            elif 'hardware' in class_name:
                return 'hardware'
            elif 'net' in class_name:
                return 'network'
            elif 'crypto' in class_name:
                return 'cryptography'
            else:
                return 'android_system'
        elif class_name.startswith('Ljava/'):
            if 'net' in class_name:
                return 'network'
            elif 'security' in class_name or 'crypto' in class_name:
                return 'cryptography'
            elif 'reflect' in class_name:
                return 'reflection'
            else:
                return 'java_standard'
        else:
            return 'other'
    
    def _assess_risk_level(self, pattern: str) -> str:
        """Assess risk level of suspicious API patterns"""
        high_risk_patterns = [
            'java.lang.Runtime.exec',
            'android.app.admin.DevicePolicyManager',
            'java.lang.reflect'
        ]
        
        medium_risk_patterns = [
            'android.telephony.SmsManager',
            'android.location.LocationManager',
            'javax.crypto'
        ]
        
        if pattern in high_risk_patterns:
            return 'high'
        elif pattern in medium_risk_patterns:
            return 'medium'
        else:
            return 'low'
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        return True