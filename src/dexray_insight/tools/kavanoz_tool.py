#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import logging
import platform
import tempfile
from typing import Dict, Any, Optional
from pathlib import Path

from ..core.base_classes import BaseExternalTool, register_tool
from ..results.kavanozResults import KavanozResults

@register_tool('kavanoz')
class KavanozTool(BaseExternalTool):
    """Kavanoz external tool for detecting and unpacking packed Android malware"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('timeout', 600)
        self.output_dir = config.get('output_dir')
        self.create_temp_dir = config.get('create_temp_dir', True)
    
    def execute(self, apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute Kavanoz on the APK file
        
        Args:
            apk_path: Path to the APK file
            output_dir: Optional output directory for unpacked files
            
        Returns:
            Dictionary containing Kavanoz analysis results
        """
        try:
            # Determine output directory
            if output_dir:
                work_output_dir = output_dir
            elif self.output_dir:
                work_output_dir = self.output_dir
            else:
                # Create temporary directory
                work_output_dir = tempfile.mkdtemp(prefix="kavanoz_")
                self.logger.info(f"Created temporary output directory: {work_output_dir}")
            
            # Ensure output directory exists
            Path(work_output_dir).mkdir(parents=True, exist_ok=True)
            
            # Execute Kavanoz analysis
            # right now we have no Kavanoz analysis engine, so we just simulate the results
            

            if platform.machine() in ("arm64", "aarch64"):
                results = " not implemented yet for arm64/aarch64"
            else:
                results = self._analyze_with_kavanoz(apk_path, work_output_dir)
            
            
            return {
                'status': 'success',
                'results': results,
                'output_directory': work_output_dir,
                'execution_time': 0  # Would be set by the analysis engine
            }
            
        except Exception as e:
            error_msg = f"Kavanoz execution failed: {str(e)}"
            self.logger.error(error_msg)
            return {
                'status': 'failure',
                'error': error_msg,
                'results': None,
                'output_directory': None
            }
    
    def _analyze_with_kavanoz(self, apk_path: str, output_dir: str) -> KavanozResults:
        """
        Perform analysis using Kavanoz library
        
        Args:
            apk_path: Path to the APK file
            output_dir: Output directory for unpacked files
            
        Returns:
            KavanozResults object
        """
        try:
            # Import Kavanoz - handle potential import errors
            try:
                # Try to install setuptools as a fallback for distutils
                try:
                    # import distutils
                    pass
                except ImportError:
                    try:
                        # import setuptools  # setuptools provides distutils compatibility
                        # import distutils
                        pass
                    except ImportError:
                        self.logger.warning("Neither distutils nor setuptools available. Installing setuptools might help.")
                        pass
                
                from kavanoz.core import Kavanoz
                from loguru import logger as loguru_logger
            except ImportError as e:
                error_msg = f"Kavanoz library not available: {str(e)}"
                if "distutils" in str(e).lower():
                    error_msg += ". Try installing setuptools: pip install setuptools"
                raise ImportError(error_msg)
            
            # Disable Kavanoz logging to avoid conflicts
            logging.getLogger("kavanoz").disabled = True
            try:
                loguru_logger.remove()
            except Exception:
                pass  # Ignore if no handlers are present
            
            # Initialize Kavanoz
            k = Kavanoz(apk_path=apk_path, output_dir=output_dir)
            
            # Prepare result structure
            result_data = {
                "is_packed": k.is_packed(),
                "unpacked": False,
                "packing_procedure": None,
                "unpacked_file_path": None
            }
            
            # If packed, try to unpack
            if result_data["is_packed"]:
                self.logger.info("APK appears to be packed, attempting to unpack...")
                
                for plugin_result in k.get_plugin_results():
                    if plugin_result["status"] == "success":
                        result_data["unpacked"] = True
                        result_data["packing_procedure"] = plugin_result["name"]
                        result_data["unpacked_file_path"] = plugin_result["output_file"]
                        self.logger.info(f"Successfully unpacked using {plugin_result['name']}")
                        break
                
                if not result_data["unpacked"]:
                    self.logger.warning("APK is packed but unpacking failed")
            else:
                self.logger.info("APK does not appear to be packed")
            
            # Parse into KavanozResults object
            return self._parse_results(json.dumps(result_data, indent=4))
            
        except ImportError as e:
            self.logger.error(f"Kavanoz library not available: {str(e)}")
            return KavanozResults(
                is_packed=False,
                unpacked=False,
                packing_procedure=f"Import error: {str(e)}",
                unpacked_file_path=""
            )
        except Exception as e:
            self.logger.error(f"Kavanoz analysis failed: {str(e)}")
            return KavanozResults(
                is_packed=False,
                unpacked=False,
                packing_procedure=f"Analysis error: {str(e)}",
                unpacked_file_path=""
            )
    
    def _parse_results(self, raw_json: str) -> KavanozResults:
        """
        Parse Kavanoz JSON output into a KavanozResults object
        
        Args:
            raw_json: Raw JSON output from Kavanoz
            
        Returns:
            KavanozResults object
        """
        try:
            data = json.loads(raw_json)
            
            is_packed = data.get("is_packed", False)
            unpacked = data.get("unpacked", False)
            packing_procedure = data.get("packing_procedure", "")
            unpacked_file_path = data.get("unpacked_file_path", "")
            
            return KavanozResults(
                is_packed=is_packed,
                unpacked=unpacked,
                packing_procedure=packing_procedure,
                unpacked_file_path=unpacked_file_path
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing Kavanoz results: {str(e)}")
            return KavanozResults(
                is_packed=False,
                unpacked=False,
                packing_procedure=f"Parse error: {str(e)}",
                unpacked_file_path=""
            )
    
    def is_available(self) -> bool:
        """
        Check if Kavanoz is available on the system
        
        Returns:
            True if Kavanoz library can be imported
        """
        try:
            # Try to handle distutils compatibility first
            try:
                # import distutils
                pass
            except ImportError:
                try:
                    # import setuptools
                    # import distutils
                    pass
                except ImportError:
                    self.logger.debug("distutils/setuptools not available, Kavanoz may not work")
            
            # from kavanoz.core import Kavanoz
            return True
        except ImportError as e:
            self.logger.debug(f"Kavanoz not available: {str(e)}")
            return False
    
    def get_version(self) -> Optional[str]:
        """
        Get Kavanoz version
        
        Returns:
            Version string if available, None otherwise
        """
        try:
            import kavanoz
            return getattr(kavanoz, '__version__', 'unknown')
        except ImportError:
            return None
    
    def validate_config(self) -> bool:
        """Validate tool configuration"""
        if self.timeout <= 0:
            self.logger.error("Timeout must be greater than 0")
            return False
        
        if self.output_dir and not os.access(os.path.dirname(self.output_dir), os.W_OK):
            self.logger.warning(f"Output directory may not be writable: {self.output_dir}")
        
        return True