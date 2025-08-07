#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import json
import shutil
import logging
from typing import Dict, Any, Optional

from ..core.base_classes import BaseExternalTool, register_tool
from ..results.apkidResults import ApkidResults, ApkidFileAnalysis

@register_tool('apkid')
class APKIDTool(BaseExternalTool):
    """APKID external tool for detecting packers, obfuscation, and anti-analysis techniques"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('timeout', 300)
        self.options = config.get('options', [])
        self.include_types = config.get('include_types', True)
        self.json_output = config.get('json_output', True)
    
    def execute(self, apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute APKID on the APK file
        
        Args:
            apk_path: Path to the APK file
            output_dir: Optional output directory (not used by APKID)
            
        Returns:
            Dictionary containing APKID analysis results
        """
        try:
            # Build command
            command = ['apkid']
            
            # Add include types option if enabled
            if self.include_types:
                command.append('--include-types')
            
            # Add JSON output option if enabled
            if self.json_output:
                command.append('-j')
            
            # Add custom options
            command.extend(self.options)
            
            # Add APK path
            command.append(apk_path)
            
            self.logger.info(f"Executing APKID: {' '.join(command)}")
            
            # Execute command
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                error_msg = f"APKID execution failed with return code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                return {
                    'status': 'failure',
                    'error': error_msg,
                    'raw_output': result.stderr,
                    'results': None
                }
            
            # Parse results
            raw_output = result.stdout
            parsed_results = self._parse_results(raw_output)
            
            return {
                'status': 'success',
                'raw_output': raw_output,
                'results': parsed_results,
                'command_executed': ' '.join(command),
                'execution_time': 0  # Would be set by the analysis engine
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"APKID execution timed out after {self.timeout} seconds"
            self.logger.error(error_msg)
            return {
                'status': 'timeout',
                'error': error_msg,
                'raw_output': '',
                'results': None
            }
        except Exception as e:
            error_msg = f"APKID execution failed: {str(e)}"
            self.logger.error(error_msg)
            return {
                'status': 'failure',
                'error': error_msg,
                'raw_output': '',
                'results': None
            }
    
    def _parse_results(self, raw_json: str) -> ApkidResults:
        """
        Parse APKID JSON output into an ApkidResults object
        
        Args:
            raw_json: Raw JSON output from APKID
            
        Returns:
            ApkidResults object
        """
        try:
            data = json.loads(raw_json)
            
            apkid_version = data.get("apkid_version", "")
            rules_sha256 = data.get("rules_sha256", "")
            files = [
                ApkidFileAnalysis(
                    filename=file["filename"],
                    matches=file.get("matches", {})
                )
                for file in data.get("files", [])
            ]
            
            return ApkidResults(
                apkid_version=apkid_version,
                files=files,
                rules_sha256=rules_sha256,
                raw_output=raw_json
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing APKID results: {str(e)}")
            return ApkidResults(
                apkid_version="",
                raw_output=f"Parse error: {str(e)}"
            )
    
    def is_available(self) -> bool:
        """
        Check if APKID is available on the system
        
        Returns:
            True if APKID is available and can be executed
        """
        try:
            return shutil.which('apkid') is not None
        except Exception:
            return False
    
    def get_version(self) -> Optional[str]:
        """
        Get APKID version
        
        Returns:
            Version string if available, None otherwise
        """
        try:
            result = subprocess.run(
                ['apkid', '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract version from output
                output = result.stdout.strip()
                if output:
                    return output
            
            return None
            
        except Exception:
            return None
    
    def validate_config(self) -> bool:
        """Validate tool configuration"""
        if self.timeout <= 0:
            self.logger.error("Timeout must be greater than 0")
            return False
        
        if not isinstance(self.options, list):
            self.logger.error("Options must be a list")
            return False
        
        return True