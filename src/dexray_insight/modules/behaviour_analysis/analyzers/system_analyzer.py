#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
System Analyzer

Detects system-level behaviors including clipboard usage, dynamic receivers,
running services access, and installed applications enumeration.
"""

import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class SystemAnalyzer:
    """Analyzer for system-level privacy behaviors"""
    
    CLIPBOARD_PATTERNS = [
        r'ClipboardManager',
        r'getSystemService.*CLIPBOARD_SERVICE',
        r'getPrimaryClip\(\)',
        r'setPrimaryClip\(\)',
        r'android\.content\.ClipboardManager'
    ]
    
    DYNAMIC_RECEIVER_PATTERNS = [
        r'registerReceiver\(',
        r'unregisterReceiver\(',
        r'BroadcastReceiver',
        r'IntentFilter.*addAction'
    ]
    
    RUNNING_SERVICES_PATTERNS = [
        r'getRunningServices\(',
        r'ActivityManager.*getRunningServices',
        r'getRunningAppProcesses\(',
        r'getRunningTasks\(',
        r'ProcessInfo'
    ]
    
    INSTALLED_APPS_PATTERNS = [
        r'getInstalledApplications\(',
        r'PackageManager.*getInstalledApplications',
        r'ApplicationInfo',
        r'queryIntentActivities\(',
        r'QUERY_ALL_PACKAGES'
    ]
    
    INSTALLED_PACKAGES_PATTERNS = [
        r'getInstalledPackages\(',
        r'PackageManager.*getInstalledPackages',
        r'PackageInfo',
        r'getPackageInfo\(',
        r'GET_INSTALLED_PACKAGES'
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_clipboard_usage(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app uses clipboard"""
        try:
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.CLIPBOARD_PATTERNS, "clipboard usage"
            )
            
            result.add_finding(
                "clipboard_usage",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application uses clipboard functionality"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Clipboard analysis failed: {e}")
            return []
    
    def analyze_dynamic_receivers(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check for dynamically registered broadcast receivers"""
        try:
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.DYNAMIC_RECEIVER_PATTERNS, "dynamic broadcast receivers"
            )
            
            result.add_finding(
                "dynamic_receivers",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application registers broadcast receivers dynamically"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Dynamic receivers analysis failed: {e}")
            return []
    
    def analyze_running_services_access(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app tries to get running services"""
        try:
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.RUNNING_SERVICES_PATTERNS, "running services access"
            )
            
            result.add_finding(
                "running_services_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application tries to access running services information"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Running services analysis failed: {e}")
            return []
    
    def analyze_installed_applications(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app gets installed applications"""
        evidence = []
        
        try:
            # Check permissions
            permissions = apk_obj.get_permissions()
            if 'android.permission.QUERY_ALL_PACKAGES' in permissions:
                evidence.append(BehaviorEvidence(
                    type='permission',
                    content='android.permission.QUERY_ALL_PACKAGES',
                    location='AndroidManifest.xml'
                ))
            
            # Search patterns
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            pattern_evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.INSTALLED_APPS_PATTERNS, "installed applications access"
            )
            evidence.extend(pattern_evidence)
            
            result.add_finding(
                "installed_applications_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application accesses installed applications list"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Installed applications analysis failed: {e}")
            return []
    
    def analyze_installed_packages(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app gets installed packages"""
        try:
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.INSTALLED_PACKAGES_PATTERNS, "installed packages access"
            )
            
            result.add_finding(
                "installed_packages_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application accesses installed packages information"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Installed packages analysis failed: {e}")
            return []