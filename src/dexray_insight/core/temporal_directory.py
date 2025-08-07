#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import zipfile
import subprocess
import logging
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime
from dataclasses import dataclass

from .configuration import Configuration

@dataclass
class TemporalDirectoryPaths:
    """Container for temporal directory paths"""
    base_dir: Path
    unzipped_dir: Path
    jadx_dir: Path
    apktool_dir: Path
    logs_dir: Path
    
    def cleanup(self):
        """Remove the entire temporal directory tree"""
        if self.base_dir.exists():
            shutil.rmtree(self.base_dir)


class TemporalDirectoryManager:
    """
    Manages temporal directory structure for APK analysis with external tool integration.
    
    Creates a structured temporary directory for each APK analysis that includes:
    - Unzipped APK contents
    - JADX decompilation results
    - Apktool extraction results
    - Tool execution logs
    """
    
    def __init__(self, config: Configuration, logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.temporal_config = config.get_temporal_analysis_config()
        self.current_paths: Optional[TemporalDirectoryPaths] = None
        
        # Validate configuration on initialization
        self._validate_configuration()
    
    def _validate_configuration(self):
        """Validate temporal analysis and tool configurations"""
        # Check temporal analysis configuration
        if not isinstance(self.temporal_config, dict):
            self.logger.warning("Temporal analysis configuration not found, using defaults")
            return
        
        # Validate base directory
        base_dir = self.temporal_config.get('base_directory', './temp_analysis')
        try:
            base_path = Path(base_dir)
            if not base_path.parent.exists():
                self.logger.warning(f"Parent directory for temporal analysis does not exist: {base_path.parent}")
        except Exception as e:
            self.logger.warning(f"Invalid base directory configuration: {e}")
        
        # Validate directory structure configuration
        dir_structure = self.temporal_config.get('directory_structure', {})
        required_folders = ['unzipped_folder', 'jadx_folder', 'apktool_folder', 'logs_folder']
        for folder_key in required_folders:
            if not dir_structure.get(folder_key):
                self.logger.warning(f"Missing directory structure configuration: {folder_key}")
        
        # Validate external tool configurations
        self._validate_tool_configuration('jadx')
        self._validate_tool_configuration('apktool')
    
    def _validate_tool_configuration(self, tool_name: str):
        """Validate configuration for a specific external tool"""
        tool_config = self.config.get_tool_config(tool_name)
        
        if not tool_config:
            self.logger.debug(f"No configuration found for {tool_name}")
            return
            
        if not tool_config.get('enabled', True):
            self.logger.debug(f"{tool_name} is disabled in configuration")
            return
            
        tool_path = tool_config.get('path')
        if not tool_path:
            self.logger.info(f"{tool_name} path not configured - tool will be skipped during analysis")
            return
            
        # Check if tool executable exists
        if not Path(tool_path).exists():
            self.logger.warning(f"{tool_name} executable not found at configured path: {tool_path}")
        elif not os.access(tool_path, os.X_OK) and tool_name == 'jadx':
            self.logger.warning(f"{tool_name} executable at {tool_path} is not executable")
        elif tool_name == 'apktool' and not tool_path.endswith('.jar'):
            self.logger.warning(f"Apktool path should point to a JAR file: {tool_path}")
        else:
            self.logger.debug(f"{tool_name} configuration validated: {tool_path}")
        
        # Validate tool-specific configurations
        if tool_name == 'apktool':
            java_options = tool_config.get('java_options', [])
            if not isinstance(java_options, list):
                self.logger.warning("Apktool java_options should be a list")
                
        timeout = tool_config.get('timeout', 600)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            self.logger.warning(f"Invalid timeout configuration for {tool_name}: {timeout}")
        
    def create_temporal_directory(self, apk_path: str, timestamp: Optional[str] = None) -> TemporalDirectoryPaths:
        """
        Create temporal directory structure for APK analysis
        
        Args:
            apk_path: Path to the APK file being analyzed
            timestamp: Optional timestamp string, if None will generate current timestamp
            
        Returns:
            TemporalDirectoryPaths object containing all directory paths
        """
        if not self.temporal_config.get('enabled', True):
            self.logger.debug("Temporal directory creation disabled in configuration")
            return None
            
        # Generate directory name based on APK name and timestamp
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            
        apk_name = Path(apk_path).stem  # Get filename without extension
        dir_name = f"dexray_{apk_name}_{timestamp}"
        
        # Create base directory
        base_dir_path = self.temporal_config.get('base_directory', './temp_analysis')
        base_dir = Path(base_dir_path) / dir_name
        
        try:
            base_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created temporal directory: {base_dir}")
            
            # Create subdirectories based on configuration
            dir_structure = self.temporal_config.get('directory_structure', {})
            unzipped_dir = base_dir / dir_structure.get('unzipped_folder', 'unzipped')
            jadx_dir = base_dir / dir_structure.get('jadx_folder', 'jadxResults')
            apktool_dir = base_dir / dir_structure.get('apktool_folder', 'apktoolResults')
            logs_dir = base_dir / dir_structure.get('logs_folder', 'logs')
            
            # Create all subdirectories
            for sub_dir in [unzipped_dir, jadx_dir, apktool_dir, logs_dir]:
                sub_dir.mkdir(exist_ok=True)
                self.logger.debug(f"Created subdirectory: {sub_dir}")
            
            paths = TemporalDirectoryPaths(
                base_dir=base_dir,
                unzipped_dir=unzipped_dir,
                jadx_dir=jadx_dir,
                apktool_dir=apktool_dir,
                logs_dir=logs_dir
            )
            
            self.current_paths = paths
            return paths
            
        except Exception as e:
            self.logger.error(f"Failed to create temporal directory structure: {e}")
            return None
    
    def unzip_apk(self, apk_path: str, target_dir: Path) -> bool:
        """
        Unzip APK contents to target directory
        
        Args:
            apk_path: Path to the APK file
            target_dir: Directory where APK contents should be extracted
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)
                
            file_count = len(list(target_dir.rglob('*')))
            self.logger.info(f"Successfully unzipped APK to {target_dir} ({file_count} files)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unzip APK {apk_path}: {e}")
            return False
    
    def run_jadx(self, apk_path: str, output_dir: Path) -> bool:
        """
        Run JADX decompilation on APK
        
        Args:
            apk_path: Path to the APK file
            output_dir: Directory where JADX results should be stored
            
        Returns:
            True if successful, False otherwise
        """
        jadx_config = self.config.get_tool_config('jadx')
        
        if not jadx_config.get('enabled', True):
            self.logger.debug("JADX is disabled in configuration")
            return False
            
        jadx_path = jadx_config.get('path')
        if not jadx_path:
            self.logger.warning("JADX path not configured, skipping JADX decompilation")
            return False
            
        if not Path(jadx_path).exists():
            self.logger.warning(f"JADX executable not found at {jadx_path}, skipping decompilation")
            return False
        
        try:
            # Build JADX command
            cmd = [jadx_path]
            cmd.extend(jadx_config.get('options', []))
            cmd.extend(['--output-dir', str(output_dir), apk_path])
            
            self.logger.info(f"Running JADX: {' '.join(cmd)}")
            
            # Create log file
            log_file = self.current_paths.logs_dir / 'jadx_output.log' if self.current_paths else None
            
            # Ensure logs directory exists
            if log_file:
                log_file.parent.mkdir(exist_ok=True)
            
            # Set up environment - preserve existing environment but fix JAVA_HOME if needed
            env = os.environ.copy()
            
            # Fix JAVA_HOME if it's invalid
            java_home = env.get('JAVA_HOME', '')
            if java_home and not Path(java_home).exists():
                self.logger.debug(f"Invalid JAVA_HOME detected: {java_home}")
                # Try to find Java executable and derive JAVA_HOME
                try:
                    java_exec = shutil.which('java')
                    if java_exec:
                        # For system Java, unset JAVA_HOME to use system default
                        if java_exec == '/usr/bin/java':
                            env.pop('JAVA_HOME', None)
                            self.logger.debug("Using system Java, removed JAVA_HOME")
                except Exception as e:
                    self.logger.debug(f"Java environment detection failed: {e}")
            
            with open(log_file, 'w') if log_file else open(os.devnull, 'w') as log_f:
                result = subprocess.run(
                    cmd,
                    timeout=jadx_config.get('timeout', 900),
                    stdout=log_f,
                    stderr=log_f,
                    text=True,
                    cwd=Path.cwd(),
                    env=env  # Use updated environment
                )
                
            # Check success by looking at output directory contents, not just return code
            java_files = list(output_dir.rglob('*.java'))
            java_count = len(java_files)
            
            if java_count > 0:
                self.logger.info(f"JADX decompilation completed successfully ({java_count} Java files generated)")
                return True
            elif result.returncode == 0:
                self.logger.warning("JADX completed with return code 0 but no Java files were generated")
                return False
            else:
                self.logger.error(f"JADX failed with return code {result.returncode}")
                if log_file and log_file.exists():
                    self.logger.debug(f"Check JADX log for details: {log_file}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"JADX execution timed out after {jadx_config.get('timeout', 900)} seconds")
            return False
        except Exception as e:
            self.logger.error(f"Failed to run JADX: {e}")
            return False
    
    def run_apktool(self, apk_path: str, output_dir: Path) -> bool:
        """
        Run apktool on APK
        
        Args:
            apk_path: Path to the APK file
            output_dir: Directory where apktool results should be stored
            
        Returns:
            True if successful, False otherwise
        """
        apktool_config = self.config.get_tool_config('apktool')
        
        if not apktool_config.get('enabled', True):
            self.logger.debug("Apktool is disabled in configuration")
            return False
            
        apktool_path = apktool_config.get('path')
        if not apktool_path:
            self.logger.warning("Apktool path not configured, skipping apktool analysis")
            return False
            
        if not Path(apktool_path).exists():
            self.logger.warning(f"Apktool JAR not found at {apktool_path}, skipping analysis")
            return False
        
        try:
            # Build apktool command
            cmd = ['java']
            cmd.extend(apktool_config.get('java_options', ['-Xmx2g']))
            cmd.extend(['-jar', apktool_path, 'decode'])
            cmd.extend(apktool_config.get('options', []))
            cmd.extend(['-f'])  # Force overwrite if directory exists
            cmd.extend(['--output', str(output_dir), apk_path])
            
            self.logger.info(f"Running Apktool: {' '.join(cmd)}")
            
            # Create log file
            log_file = self.current_paths.logs_dir / 'apktool_output.log' if self.current_paths else None
            
            # Ensure logs directory exists
            if log_file:
                log_file.parent.mkdir(exist_ok=True)
            
            # Set up environment - fix JAVA_HOME if needed for Java tools
            env = os.environ.copy()
            
            # Fix JAVA_HOME if it's invalid
            java_home = env.get('JAVA_HOME', '')
            if java_home and not Path(java_home).exists():
                self.logger.debug(f"Invalid JAVA_HOME detected: {java_home}")
                # For system Java, unset JAVA_HOME to use system default
                try:
                    java_exec = shutil.which('java')
                    if java_exec == '/usr/bin/java':
                        env.pop('JAVA_HOME', None)
                        self.logger.debug("Using system Java, removed JAVA_HOME")
                except Exception as e:
                    self.logger.debug(f"Java environment detection failed: {e}")
            
            with open(log_file, 'w') if log_file else open(os.devnull, 'w') as log_f:
                result = subprocess.run(
                    cmd,
                    timeout=apktool_config.get('timeout', 600),
                    stdout=log_f,
                    stderr=log_f,
                    text=True,
                    cwd=Path.cwd(),
                    env=env
                )
                
            # Check success by looking at output directory contents, not just return code
            # Apktool should create AndroidManifest.xml and other key files
            expected_files = ['AndroidManifest.xml', 'apktool.yml']
            found_files = [f for f in expected_files if (output_dir / f).exists()]
            
            if len(found_files) >= 1:  # At least one expected file should exist
                files_count = len(list(output_dir.rglob('*')))
                self.logger.info(f"Apktool analysis completed successfully ({files_count} files generated)")
                return True
            elif result.returncode == 0:
                self.logger.warning("Apktool completed with return code 0 but expected files were not generated")
                return False
            else:
                self.logger.error(f"Apktool failed with return code {result.returncode}")
                if log_file and log_file.exists():
                    self.logger.debug(f"Check Apktool log for details: {log_file}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Apktool execution timed out after {apktool_config.get('timeout', 600)} seconds")
            return False
        except Exception as e:
            self.logger.error(f"Failed to run Apktool: {e}")
            return False
    
    def check_tool_availability(self, tool_name: str) -> bool:
        """
        Check if external tool is available and properly configured
        
        Args:
            tool_name: Name of the tool ('jadx' or 'apktool')
            
        Returns:
            True if tool is available and configured, False otherwise
        """
        tool_config = self.config.get_tool_config(tool_name)
        
        if not tool_config.get('enabled', True):
            return False
            
        tool_path = tool_config.get('path')
        if not tool_path:
            return False
            
        return Path(tool_path).exists()
    
    def process_apk_with_tools(self, apk_path: str, paths: TemporalDirectoryPaths) -> Dict[str, bool]:
        """
        Process APK with all configured external tools
        
        Args:
            apk_path: Path to the APK file
            paths: TemporalDirectoryPaths object with directory structure
            
        Returns:
            Dictionary with tool execution results
        """
        results = {}
        
        # Unzip APK
        self.logger.info("Extracting APK contents...")
        results['unzip'] = self.unzip_apk(apk_path, paths.unzipped_dir)
        
        # Run JADX if available
        if self.check_tool_availability('jadx'):
            self.logger.info("Running JADX decompilation...")
            results['jadx'] = self.run_jadx(apk_path, paths.jadx_dir)
        else:
            self.logger.info("JADX not available or disabled, skipping decompilation")
            results['jadx'] = False
        
        # Run apktool if available
        if self.check_tool_availability('apktool'):
            self.logger.info("Running Apktool analysis...")
            results['apktool'] = self.run_apktool(apk_path, paths.apktool_dir)
        else:
            self.logger.info("Apktool not available or disabled, skipping analysis")
            results['apktool'] = False
            
        return results
    
    def cleanup_temporal_directory(self, paths: Optional[TemporalDirectoryPaths] = None, force: bool = False) -> bool:
        """
        Cleanup temporal directory after analysis
        
        Args:
            paths: TemporalDirectoryPaths to cleanup, uses current if None
            force: Force cleanup even if preserve_on_error is True
            
        Returns:
            True if cleanup was successful or skipped, False if failed
        """
        if paths is None:
            paths = self.current_paths
            
        if paths is None:
            return True
            
        cleanup_enabled = self.temporal_config.get('cleanup_after_analysis', False)
        
        if not cleanup_enabled and not force:
            self.logger.debug(f"Cleanup disabled, preserving temporal directory: {paths.base_dir}")
            return True
            
        try:
            paths.cleanup()
            self.logger.info(f"Successfully cleaned up temporal directory: {paths.base_dir}")
            
            if paths == self.current_paths:
                self.current_paths = None
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup temporal directory {paths.base_dir}: {e}")
            return False
    
    def get_current_paths(self) -> Optional[TemporalDirectoryPaths]:
        """Get current temporal directory paths"""
        return self.current_paths
        
    def __enter__(self):
        """Context manager entry"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup on exit"""
        preserve_on_error = self.temporal_config.get('preserve_on_error', True)
        
        # If there was an exception and preserve_on_error is True, don't cleanup
        if exc_type is not None and preserve_on_error:
            self.logger.info("Analysis failed, preserving temporal directory for debugging")
            return
            
        # Normal cleanup
        self.cleanup_temporal_directory()