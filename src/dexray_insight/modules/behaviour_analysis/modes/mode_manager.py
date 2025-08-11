#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mode Manager

Manages analysis modes (fast vs deep) and coordinates the appropriate
analysis strategy based on configuration and available objects.
"""

import logging
from typing import Dict, Any, Optional, Tuple

from dexray_insight.core.base_classes import AnalysisContext


class ModeManager:
    """Manages behavior analysis modes and object availability"""
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
    
    def determine_analysis_mode(self, context: AnalysisContext) -> Tuple[bool, str]:
        """
        Determine whether to run in fast or deep mode
        
        Returns:
            Tuple of (is_deep_mode, mode_description)
        """
        try:
            # Check if deep mode is explicitly enabled
            deep_mode = (self.config.get('deep_mode', False) or 
                        context.config.get('behaviour_analysis', {}).get('deep_mode', False))
            
            if deep_mode:
                return True, "DEEP"
            else:
                return False, "FAST"
                
        except Exception as e:
            self.logger.error(f"Error determining analysis mode: {e}")
            # Default to fast mode if there's an error
            return False, "FAST"
    
    def is_module_enabled(self, context: AnalysisContext) -> bool:
        """Check if the behavior analysis module is enabled"""
        try:
            return context.config.get('behaviour_analysis', {}).get('enabled', True)
        except Exception as e:
            self.logger.error(f"Error checking module enablement: {e}")
            return True  # Default to enabled
    
    def prepare_analysis_objects(self, context: AnalysisContext, is_deep_mode: bool) -> Dict[str, Any]:
        """
        Prepare analysis objects based on mode
        
        Returns:
            Dictionary containing the prepared objects for analysis
        """
        try:
            if not context.androguard_obj:
                raise ValueError("Androguard object not available in context")
            
            # Get APK object (needed for both modes)
            apk_obj = context.androguard_obj.get_androguard_apk()
            
            analysis_objects = {
                'apk_obj': apk_obj,
                'dex_obj': None,
                'dx_obj': None,
                'mode': 'fast'
            }
            
            if is_deep_mode:
                # Get DEX objects for deep analysis
                dex_obj = context.androguard_obj.get_androguard_dex()
                dx_obj = context.androguard_obj.get_androguard_analysisObj()
                
                analysis_objects.update({
                    'dex_obj': dex_obj,
                    'dx_obj': dx_obj,
                    'mode': 'deep'
                })
                
                # Store objects in context for security analysis access
                context.deep_analysis_objects = {
                    'apk_obj': apk_obj,
                    'dex_obj': dex_obj,
                    'dx_obj': dx_obj
                }
            else:
                # Store only APK object in fast mode
                context.fast_analysis_objects = {
                    'apk_obj': apk_obj
                }
            
            return analysis_objects
            
        except Exception as e:
            self.logger.error(f"Error preparing analysis objects: {e}")
            raise
    
    def store_analysis_objects_in_result(self, result, analysis_objects: Dict[str, Any]) -> None:
        """Store androguard objects in the result for security analysis access"""
        try:
            if analysis_objects['mode'] == 'deep':
                result.androguard_objects = {
                    'mode': 'deep',
                    'apk_obj': analysis_objects['apk_obj'],
                    'dex_obj': analysis_objects['dex_obj'],
                    'dx_obj': analysis_objects['dx_obj']
                }
            else:
                result.androguard_objects = {
                    'mode': 'fast',
                    'apk_obj': analysis_objects['apk_obj'],
                    'dex_obj': None,
                    'dx_obj': None
                }
        except Exception as e:
            self.logger.error(f"Error storing analysis objects in result: {e}")
    
    def generate_analysis_summary(self, result, is_deep_mode: bool) -> Dict[str, Any]:
        """Generate analysis summary based on results and mode"""
        try:
            detected_count = len(result.get_detected_features())
            total_count = len(result.findings)
            
            summary = {
                'total_features_analyzed': total_count,
                'features_detected': detected_count,
                'detection_rate': round(detected_count / total_count * 100, 2) if total_count > 0 else 0,
                'analysis_mode': 'deep' if is_deep_mode else 'fast'
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating analysis summary: {e}")
            return {
                'total_features_analyzed': 0,
                'features_detected': 0,
                'detection_rate': 0,
                'analysis_mode': 'fast'
            }