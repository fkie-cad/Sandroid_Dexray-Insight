#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base class for native binary analysis modules.

This module provides the foundation for all native analysis modules that use
radare2/r2pipe to analyze native binaries (.so files) in Android APKs.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass

try:
    import r2pipe
except ImportError:
    r2pipe = None

@dataclass
class NativeStringSource:
    """Represents a string extracted from a native binary with source information"""
    content: str                    # The actual string content
    source_type: str = "native"     # Always "native" for native binaries
    file_path: str = ""             # Path to the native binary (e.g., "lib/arm64-v8a/libexample.so")
    extraction_method: str = ""     # Method used to extract the string
    offset: Optional[int] = None    # Offset in the binary where string was found
    encoding: str = "utf-8"         # Detected or assumed encoding
    confidence: float = 1.0         # Confidence in the extraction (0.0-1.0)

@dataclass
class NativeBinaryInfo:
    """Information about a native binary being analyzed"""
    file_path: Path                 # Full path to the binary file
    relative_path: str              # Relative path within APK (e.g., "lib/arm64-v8a/libexample.so")
    architecture: str               # Architecture (e.g., "arm64-v8a")
    file_size: int                  # File size in bytes
    file_name: str                  # Just the filename (e.g., "libexample.so")

@dataclass
class NativeAnalysisResult:
    """Result container for native binary analysis"""
    binary_info: NativeBinaryInfo
    module_name: str
    success: bool
    error_message: Optional[str] = None
    execution_time: float = 0.0
    strings_found: List[NativeStringSource] = None
    additional_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.strings_found is None:
            self.strings_found = []
        if self.additional_data is None:
            self.additional_data = {}

class BaseNativeModule(ABC):
    """
    Abstract base class for native binary analysis modules.
    
    This class provides the interface that all native analysis modules must implement
    to integrate with the native analysis framework.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the native analysis module.
        
        Args:
            config: Configuration dictionary for this module
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.name = self.__class__.__name__
        self.enabled = config.get('enabled', True)
        
        # Check if r2pipe is available
        if r2pipe is None:
            self.logger.warning("r2pipe not available - native analysis will be disabled")
            self.enabled = False
    
    @abstractmethod
    def analyze_binary(self, binary_info: NativeBinaryInfo, r2: Any) -> NativeAnalysisResult:
        """
        Analyze a single native binary.
        
        Args:
            binary_info: Information about the binary being analyzed
            r2: r2pipe connection to the binary
            
        Returns:
            NativeAnalysisResult containing analysis results
        """
        pass
    
    def can_analyze(self, binary_info: NativeBinaryInfo) -> bool:
        """
        Check if this module can/should analyze the given binary.
        
        Args:
            binary_info: Information about the binary
            
        Returns:
            True if the module should analyze this binary, False otherwise
        """
        return self.enabled
    
    def get_module_name(self) -> str:
        """Get the module name for identification"""
        return self.name
    
    def is_enabled(self) -> bool:
        """Check if the module is enabled"""
        return self.enabled
    
    def get_dependencies(self) -> List[str]:
        """
        Get list of dependencies that must be satisfied before this module can run.
        
        Returns:
            List of module names that this module depends on
        """
        return []  # Most native modules have no dependencies
    
    def _extract_strings_with_r2(self, r2: Any, min_length: int = 4, max_length: int = 1024) -> List[NativeStringSource]:
        """
        Helper method to extract strings using radare2.
        
        Args:
            r2: r2pipe connection
            min_length: Minimum string length
            max_length: Maximum string length
            
        Returns:
            List of extracted strings with source information
        """
        strings = []
        
        try:
            # Use r2's string extraction command
            string_results = r2.cmd("iz")  # Extract strings from data sections
            
            if string_results:
                lines = string_results.strip().split('\n')
                for line in lines:
                    if not line.strip():
                        continue
                        
                    # Parse r2 string output format
                    parts = line.split(None, 4)
                    if len(parts) >= 5:
                        try:
                            offset_str = parts[1]
                            length_str = parts[2]
                            string_content = parts[4] if len(parts) > 4 else ""
                            
                            # Parse offset and length
                            offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                            length = int(length_str)
                            
                            # Filter by length
                            if min_length <= length <= max_length and string_content:
                                strings.append(NativeStringSource(
                                    content=string_content,
                                    extraction_method="r2_iz_command",
                                    offset=offset,
                                    encoding="utf-8"  # r2 usually handles encoding
                                ))
                        except (ValueError, IndexError):
                            continue
                            
        except Exception as e:
            self.logger.debug(f"Error extracting strings with r2: {e}")
        
        return strings
    
    def _safe_r2_command(self, r2: Any, command: str, default: Any = None) -> Any:
        """
        Safely execute an r2 command with error handling.
        
        Args:
            r2: r2pipe connection
            command: r2 command to execute
            default: Default value to return on error
            
        Returns:
            Command result or default value on error
        """
        try:
            return r2.cmd(command)
        except Exception as e:
            self.logger.debug(f"r2 command '{command}' failed: {e}")
            return default