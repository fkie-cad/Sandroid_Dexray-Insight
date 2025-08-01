#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
from typing import List, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module

try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    from androguard.core.apk import APK

@dataclass
class PermissionAnalysisResult(BaseResult):
    """Result class for permission analysis"""
    all_permissions: List[str] = None
    critical_permissions: List[str] = None
    permissions_used: int = 0
    critical_permissions_found: int = 0
    
    def __post_init__(self):
        if self.all_permissions is None:
            self.all_permissions = []
        if self.critical_permissions is None:
            self.critical_permissions = []
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'all_permissions': self.all_permissions,
            'critical_permissions': self.critical_permissions,
            'permissions_used': self.permissions_used,
            'critical_permissions_found': self.critical_permissions_found
        })
        return base_dict

@register_module('permission_analysis')
class PermissionAnalysisModule(BaseAnalysisModule):
    """Permission analysis module for detecting critical Android permissions"""
    
    # Default critical permissions list
    DEFAULT_CRITICAL_PERMISSIONS = [
        "SEND_SMS", "SEND_SMS_NO_CONFIRMATION", "CALL_PHONE",
        "RECEIVE_SMS", "RECEIVE_MMS", "READ_SMS", "WRITE_SMS", "RECEIVE_WAP_PUSH",
        "READ_CONTACTS", "WRITE_CONTACTS", "READ_PROFILE", "WRITE_PROFILE", "READ_CALENDAR",
        "WRITE_CALENDAR", "READ_USER_DICTIONARY", "READ_HISTORY_BOOKMARKS",
        "WRITE_HISTORY_BOOKMARKS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "ACCESS_MOCK_LOCATION", "USE_SIP", "GET_ACCOUNTS", "AUTHENTICATE_ACCOUNTS",
        "USE_CREDENTIALS", "MANAGE_ACCOUNTS", "RECORD_AUDIO", "CAMERA",
        "PROCESS_OUTGOING_CALLS", "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE",
        "READ_EXTERNAL_STORAGE", "WRITE_SETTINGS", "GET_TASKS", "SYSTEM_ALERT_WINDOW",
        "SET_ANIMATION_SCALE", "PERSISTENT_ACTIVITY", "MOUNT_UNMOUNT_FILESYSTEMS",
        "MOUNT_FORMAT_FILESYSTEMS", "WRITE_APN_SETTINGS", "SUBSCRIBED_FEEDS_WRITE",
        "READ_LOGS", "SET_DEBUG_APP", "SET_PROCESS_LIMIT", "SET_ALWAYS_FINISH", "SIGNAL_PERSISTENT_PROCESSES",
        "REQUEST_INSTALL_PACKAGES", "ADD_VOICEMAIL", "ACCEPT_HANDOVER", "ANSWER_PHONE_CALLS",
        "BODY_SENSORS", "READ_CALL_LOG", "READ_PHONE_NUMBERS", "WRITE_CALL_LOG",
        "ACCESS_BACKGROUND_LOCATION", "ACCESS_MEDIA_LOCATION", "ACTIVITY_RECOGNITION",
        "MANAGE_EXTERNAL_STORAGE", "READ_PRECISE_PHONE_STATE", "BLUETOOTH_ADVERTISE",
        "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "BODY_SENSORS_BACKGROUND",
        "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "READ_MEDIA_AUDIO",
        "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_VISUAL_USER_SELECTED",
        "UWB_RANGING"
    ]
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.critical_permissions_file = config.get('critical_permissions_file')
        self.use_default_list = config.get('use_default_critical_list', True)
        self.critical_permissions = self._load_critical_permissions()
    
    def get_dependencies(self) -> List[str]:
        """No dependencies for permission analysis"""
        return []
    
    def _load_critical_permissions(self) -> List[str]:
        """Load critical permissions from file or use default list"""
        if self.critical_permissions_file:
            try:
                path = Path(self.critical_permissions_file)
                if path.exists():
                    with open(path, 'r') as f:
                        content = f.read().strip()
                        # Support both line-separated and comma-separated formats
                        if ',' in content:
                            permissions = [p.strip() for p in content.split(',')]
                        else:
                            permissions = content.split()
                        self.logger.info(f"Loaded {len(permissions)} critical permissions from {self.critical_permissions_file}")
                        return permissions
                else:
                    self.logger.warning(f"Critical permissions file not found: {self.critical_permissions_file}")
            except Exception as e:
                self.logger.error(f"Failed to load critical permissions file: {str(e)}")
        
        if self.use_default_list:
            self.logger.info(f"Using default critical permissions list with {len(self.DEFAULT_CRITICAL_PERMISSIONS)} permissions")
            return self.DEFAULT_CRITICAL_PERMISSIONS
        
        return []
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> PermissionAnalysisResult:
        """
        Perform permission analysis on the APK
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            PermissionAnalysisResult with analysis results
        """
        start_time = time.time()
        
        try:
            # Use existing androguard object if available
            if context.androguard_obj:
                # Try to get permissions from the existing androguard object
                # This would need to be adapted based on the actual interface
                all_permissions = []  # Placeholder - would extract from androguard_obj
            else:
                # Create new APK instance
                apk = APK(apk_path)
                all_permissions = apk.get_permissions()
            
            # Find critical permissions
            found_critical_permissions = []
            for permission in all_permissions:
                for critical_permission in self.critical_permissions:
                    if critical_permission in permission:
                        found_critical_permissions.append(permission)
                        break
            
            execution_time = time.time() - start_time
            
            return PermissionAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                all_permissions=all_permissions,
                critical_permissions=found_critical_permissions,
                permissions_used=len(all_permissions),
                critical_permissions_found=len(found_critical_permissions)
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Permission analysis failed: {str(e)}")
            
            return PermissionAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                all_permissions=[],
                critical_permissions=[],
                permissions_used=0,
                critical_permissions_found=0
            )
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        if self.critical_permissions_file:
            path = Path(self.critical_permissions_file)
            if not path.exists():
                self.logger.warning(f"Critical permissions file does not exist: {self.critical_permissions_file}")
        
        if not self.critical_permissions:
            self.logger.warning("No critical permissions loaded")
            return False
        
        return True