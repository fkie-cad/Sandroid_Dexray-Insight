#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment

@register_assessment('broken_access_control')
class BrokenAccessControlAssessment(BaseSecurityAssessment):
    """OWASP A01:2021 - Broken Access Control vulnerability assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A01:2021-Broken Access Control"
        
        self.check_exported_components = config.get('check_exported_components', True)
        self.check_permissions = config.get('check_permissions', True)
        
        # Dangerous permissions that may indicate access control issues
        self.dangerous_permissions = [
            'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE',
            'WRITE_SETTINGS', 'WRITE_SECURE_SETTINGS', 'SYSTEM_ALERT_WINDOW',
            'REQUEST_INSTALL_PACKAGES', 'INSTALL_PACKAGES', 'DELETE_PACKAGES',
            'GET_TASKS', 'REORDER_TASKS', 'KILL_BACKGROUND_PROCESSES',
            'READ_LOGS', 'WRITE_APN_SETTINGS', 'MOUNT_UNMOUNT_FILESYSTEMS',
            'DEVICE_POWER', 'MODIFY_PHONE_STATE', 'CALL_PRIVILEGED'
        ]
        
        # Component types that should typically not be exported
        self.sensitive_component_patterns = [
            'admin', 'config', 'settings', 'debug', 'test', 'internal'
        ]
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Assess for broken access control vulnerabilities
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to access control issues
        """
        findings = []
        
        try:
            # Check exported components
            if self.check_exported_components:
                exported_findings = self._assess_exported_components(analysis_results)
                findings.extend(exported_findings)
            
            # Check dangerous permissions
            if self.check_permissions:
                permission_findings = self._assess_dangerous_permissions(analysis_results)
                findings.extend(permission_findings)
            
            # Check intent filter risks
            intent_findings = self._assess_intent_filter_risks(analysis_results)
            findings.extend(intent_findings)
            
        except Exception as e:
            self.logger.error(f"Broken access control assessment failed: {str(e)}")
        
        return findings
    
    def _assess_exported_components(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess exported components for access control issues"""
        findings = []
        
        # Get manifest analysis results
        manifest_results = analysis_results.get('manifest_analysis', {})
        if hasattr(manifest_results, 'to_dict'):
            manifest_data = manifest_results.to_dict()
        else:
            manifest_data = manifest_results
        
        if not isinstance(manifest_data, dict):
            return findings
        
        # Check activities
        activities = manifest_data.get('activities', [])
        exported_activities = self._find_potentially_exported_components(activities, 'activity')
        
        # Check services
        services = manifest_data.get('services', [])
        exported_services = self._find_potentially_exported_components(services, 'service')
        
        # Check receivers
        receivers = manifest_data.get('receivers', [])
        exported_receivers = self._find_potentially_exported_components(receivers, 'receiver')
        
        # Check content providers
        providers = manifest_data.get('content_providers', [])
        exported_providers = self._find_potentially_exported_components(providers, 'provider')
        
        all_exported = exported_activities + exported_services + exported_receivers + exported_providers
        
        if all_exported:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Potentially Unsafe Exported Components",
                description="Components that may be exported without proper access controls, allowing unauthorized access from other applications.",
                evidence=all_exported,
                recommendations=[
                    "Review all exported components and ensure they require appropriate permissions",
                    "Use explicit intent filters rather than implicit ones where possible",
                    "Implement proper authentication and authorization in exported components",
                    "Consider making components non-exported if they don't need to be accessed by other apps",
                    "Use signature-level permissions for sensitive inter-app communication"
                ]
            ))
        
        return findings
    
    def _find_potentially_exported_components(self, components: List[str], component_type: str) -> List[str]:
        """Find components that may be exported and potentially unsafe"""
        potentially_unsafe = []
        
        for component in components:
            if isinstance(component, str):
                component_name = component.lower()
                
                # Check for sensitive patterns in component names
                for pattern in self.sensitive_component_patterns:
                    if pattern in component_name:
                        potentially_unsafe.append(f"{component_type.capitalize()}: {component} (contains '{pattern}')")
                        break
        
        return potentially_unsafe
    
    def _assess_dangerous_permissions(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess dangerous permissions that may indicate access control issues"""
        findings = []
        
        # Get permission analysis results
        permission_results = analysis_results.get('permission_analysis', {})
        if hasattr(permission_results, 'to_dict'):
            permission_data = permission_results.to_dict()
        else:
            permission_data = permission_results
        
        if not isinstance(permission_data, dict):
            return findings
        
        all_permissions = permission_data.get('all_permissions', [])
        dangerous_found = []
        
        for permission in all_permissions:
            if isinstance(permission, str):
                for dangerous_perm in self.dangerous_permissions:
                    if dangerous_perm in permission:
                        dangerous_found.append(permission)
                        break
        
        if dangerous_found:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Dangerous Permissions Detected",
                description="Application requests permissions that could bypass normal access controls or grant elevated privileges.",
                evidence=[f"Permission: {perm}" for perm in dangerous_found],
                recommendations=[
                    "Review all requested permissions and ensure they are necessary",
                    "Use runtime permissions (Android 6.0+) for sensitive permissions",
                    "Implement proper permission checks before accessing protected resources",
                    "Follow the principle of least privilege",
                    "Consider alternative approaches that require fewer permissions"
                ]
            ))
        
        return findings
    
    def _assess_intent_filter_risks(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess intent filters for access control risks"""
        findings = []
        
        # Get manifest analysis results
        manifest_results = analysis_results.get('manifest_analysis', {})
        if hasattr(manifest_results, 'to_dict'):
            manifest_data = manifest_results.to_dict()
        else:
            manifest_data = manifest_results
        
        if not isinstance(manifest_data, dict):
            return findings
        
        intent_filters = manifest_data.get('intent_filters', [])
        risky_filters = []
        
        for intent_filter in intent_filters:
            if isinstance(intent_filter, dict):
                component_name = intent_filter.get('component_name', '')
                filters = intent_filter.get('filters', [])
                
                # Check for overly broad intent filters
                if self._is_risky_intent_filter(filters):
                    risky_filters.append(f"{intent_filter.get('component_type', 'Component')}: {component_name}")
        
        if risky_filters:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Potentially Risky Intent Filters",
                description="Intent filters that may allow unauthorized access to components or handle sensitive actions without proper access controls.",
                evidence=risky_filters,
                recommendations=[
                    "Review intent filters to ensure they are as specific as possible",
                    "Implement proper authentication in components that handle sensitive intents",
                    "Use custom permissions to protect sensitive intent handlers",
                    "Validate all intent data before processing",
                    "Consider using explicit intents where possible"
                ]
            ))
        
        return findings
    
    def _is_risky_intent_filter(self, filters) -> bool:
        """Check if intent filters pose access control risks"""
        # This is a simplified check - in a real implementation,
        # you would parse the actual intent filter structure
        
        risky_actions = [
            'android.intent.action.BOOT_COMPLETED',
            'android.intent.action.PACKAGE_INSTALL',
            'android.intent.action.PACKAGE_REMOVED',
            'android.provider.Telephony.SMS_RECEIVED',
            'android.intent.action.PHONE_STATE'
        ]
        
        if isinstance(filters, list):
            for filter_item in filters:
                if isinstance(filter_item, str):
                    for risky_action in risky_actions:
                        if risky_action in filter_item:
                            return True
        
        return False