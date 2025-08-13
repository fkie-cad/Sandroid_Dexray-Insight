#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Media Analyzer

Detects when applications attempt to access camera, microphone, 
and other media-related functionality.
"""

import logging
from typing import List, Optional

from ..models.behavior_evidence import BehaviorEvidence


class MediaAnalyzer:
    """Analyzer for media and hardware access behaviors"""
    
    CAMERA_PATTERNS = [
        r'Camera\.open\(',
        r'camera2\.CameraManager',
        r'SurfaceView',
        r'MediaRecorder',
        r'CAMERA'
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_camera_access(self, apk_obj, dex_obj, dx_obj, result) -> List[BehaviorEvidence]:
        """Check if app tries to access camera"""
        evidence = []
        
        try:
            # Check permissions
            permissions = apk_obj.get_permissions()
            camera_permissions = [
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO'
            ]
            
            for perm in camera_permissions:
                if perm in permissions:
                    evidence.append(BehaviorEvidence(
                        type='permission',
                        content=perm,
                        location='AndroidManifest.xml'
                    ))
            
            # Search patterns
            from ..engines.pattern_search_engine import PatternSearchEngine
            search_engine = PatternSearchEngine(self.logger)
            pattern_evidence = search_engine.search_patterns_in_apk(
                apk_obj, dex_obj, dx_obj, self.CAMERA_PATTERNS, "camera access"
            )
            evidence.extend(pattern_evidence)
            
            result.add_finding(
                "camera_access",
                len(evidence) > 0,
                [ev.to_dict() for ev in evidence],
                "Application attempts to access camera"
            )
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Camera analysis failed: {e}")
            return []