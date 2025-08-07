#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Native String Extraction Module

This module extracts strings from native binaries (.so files) using radare2.
The extracted strings are then made available to other analysis modules for
pattern matching, tracker detection, and security analysis.
"""

import time
import re
from typing import Dict, Any, Optional, List

from .base_native_module import BaseNativeModule, NativeBinaryInfo, NativeAnalysisResult, NativeStringSource

class NativeStringExtractionModule(BaseNativeModule):
    """
    Native module for extracting strings from native binaries.
    
    This module uses radare2's string extraction capabilities to find readable
    strings in native binaries and makes them available for further analysis.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[Any] = None):
        super().__init__(config, logger)
        
        # Configuration
        self.min_length = config.get('min_string_length', 4)
        self.max_length = config.get('max_string_length', 1024)
        self.encoding = config.get('encoding', 'utf-8')
        self.fallback_encodings = config.get('fallback_encodings', ['latin1', 'ascii'])
        
        # String filtering patterns (to reduce noise)
        self.noise_patterns = [
            r'^[0-9.]+$',           # Pure numbers/versions
            r'^[A-Fa-f0-9]+$',      # Hexadecimal strings
            r'^[\x00-\x1f]+$',      # Control characters only
            r'^[^A-Za-z]*$'         # No alphabetic characters
        ]
        self.compiled_noise_patterns = [re.compile(pattern) for pattern in self.noise_patterns]
    
    def analyze_binary(self, binary_info: NativeBinaryInfo, r2: Any) -> NativeAnalysisResult:
        """
        Extract strings from a native binary using radare2.
        
        Args:
            binary_info: Information about the binary being analyzed
            r2: r2pipe connection to the binary
            
        Returns:
            NativeAnalysisResult with extracted strings
        """
        start_time = time.time()
        
        try:
            self.logger.debug(f"Extracting strings from {binary_info.file_name}")
            
            # Extract strings using multiple r2 commands
            strings_found = []
            
            # Method 1: Use r2's iz command (strings in data sections)
            strings_found.extend(self._extract_strings_iz(r2, binary_info))
            
            # Method 2: Use r2's izz command (strings in all sections)
            strings_found.extend(self._extract_strings_izz(r2, binary_info))
            
            # Remove duplicates while preserving order
            unique_strings = self._deduplicate_strings(strings_found)
            
            # Filter noise
            filtered_strings = self._filter_noise_strings(unique_strings)
            
            self.logger.debug(f"Extracted {len(filtered_strings)} strings from {binary_info.file_name}")
            
            return NativeAnalysisResult(
                binary_info=binary_info,
                module_name=self.get_module_name(),
                success=True,
                execution_time=time.time() - start_time,
                strings_found=filtered_strings,
                additional_data={
                    'total_strings_before_filtering': len(unique_strings),
                    'strings_after_filtering': len(filtered_strings),
                    'filter_ratio': len(filtered_strings) / max(len(unique_strings), 1)
                }
            )
            
        except Exception as e:
            self.logger.error(f"String extraction failed for {binary_info.file_name}: {e}")
            return NativeAnalysisResult(
                binary_info=binary_info,
                module_name=self.get_module_name(),
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time
            )
    
    def _extract_strings_iz(self, r2: Any, binary_info: NativeBinaryInfo) -> List[NativeStringSource]:
        """Extract strings using r2's iz command (data sections only)"""
        strings = []
        
        try:
            # Get strings from data sections
            result = self._safe_r2_command(r2, "izj", "[]")  # JSON format for easier parsing
            
            if result and result != "[]":
                import json
                try:
                    string_objects = json.loads(result)
                    for obj in string_objects:
                        if isinstance(obj, dict):
                            string_content = obj.get('string', '')
                            offset = obj.get('vaddr', obj.get('paddr', 0))
                            length = obj.get('length', len(string_content))
                            
                            if self._is_valid_string_length(string_content):
                                strings.append(NativeStringSource(
                                    content=string_content,
                                    file_path=binary_info.relative_path,
                                    extraction_method="r2_iz_data_sections",
                                    offset=offset,
                                    encoding=self.encoding,
                                    confidence=0.9  # High confidence from data sections
                                ))
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    strings.extend(self._parse_iz_text_output(result, binary_info, "r2_iz_data_sections"))
                    
        except Exception as e:
            self.logger.debug(f"iz command failed: {e}")
        
        return strings
    
    def _extract_strings_izz(self, r2: Any, binary_info: NativeBinaryInfo) -> List[NativeStringSource]:
        """Extract strings using r2's izz command (all sections)"""
        strings = []
        
        try:
            # Get strings from all sections
            result = self._safe_r2_command(r2, "izzj", "[]")  # JSON format
            
            if result and result != "[]":
                import json
                try:
                    string_objects = json.loads(result)
                    for obj in string_objects:
                        if isinstance(obj, dict):
                            string_content = obj.get('string', '')
                            offset = obj.get('vaddr', obj.get('paddr', 0))
                            section = obj.get('section', 'unknown')
                            
                            if self._is_valid_string_length(string_content):
                                strings.append(NativeStringSource(
                                    content=string_content,
                                    file_path=binary_info.relative_path,
                                    extraction_method=f"r2_izz_all_sections_{section}",
                                    offset=offset,
                                    encoding=self.encoding,
                                    confidence=0.8  # Slightly lower confidence from all sections
                                ))
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    strings.extend(self._parse_iz_text_output(result, binary_info, "r2_izz_all_sections"))
                    
        except Exception as e:
            self.logger.debug(f"izz command failed: {e}")
        
        return strings
    
    def _parse_iz_text_output(self, output: str, binary_info: NativeBinaryInfo, method: str) -> List[NativeStringSource]:
        """Parse text output from iz/izz commands as fallback"""
        strings = []
        
        if not output or not output.strip():
            return strings
        
        lines = output.strip().split('\n')
        for line in lines:
            if not line.strip():
                continue
                
            # Parse r2 string output format
            # Format typically: [ordinal] [offset] [length] [size] [section] string_content
            parts = line.split(None, 5)
            if len(parts) >= 6:
                try:
                    offset_str = parts[1]
                    string_content = parts[5]
                    
                    # Parse offset
                    offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                    
                    if self._is_valid_string_length(string_content):
                        strings.append(NativeStringSource(
                            content=string_content,
                            file_path=binary_info.relative_path,
                            extraction_method=method,
                            offset=offset,
                            encoding=self.encoding,
                            confidence=0.7  # Lower confidence for text parsing
                        ))
                except (ValueError, IndexError):
                    continue
        
        return strings
    
    def _is_valid_string_length(self, string_content: str) -> bool:
        """Check if string meets length requirements"""
        if not string_content:
            return False
        return self.min_length <= len(string_content) <= self.max_length
    
    def _deduplicate_strings(self, strings: List[NativeStringSource]) -> List[NativeStringSource]:
        """Remove duplicate strings while preserving order"""
        seen_contents = set()
        unique_strings = []
        
        for string_obj in strings:
            if string_obj.content not in seen_contents:
                seen_contents.add(string_obj.content)
                unique_strings.append(string_obj)
        
        return unique_strings
    
    def _filter_noise_strings(self, strings: List[NativeStringSource]) -> List[NativeStringSource]:
        """Filter out noise strings that are unlikely to be useful"""
        filtered = []
        
        for string_obj in strings:
            content = string_obj.content
            
            # Skip empty or very short strings
            if not content or len(content.strip()) < self.min_length:
                continue
            
            # Check noise patterns
            is_noise = False
            for pattern in self.compiled_noise_patterns:
                if pattern.match(content):
                    is_noise = True
                    break
            
            if not is_noise:
                filtered.append(string_obj)
            else:
                self.logger.debug(f"Filtered noise string: {content[:50]}...")
        
        return filtered
    
    def can_analyze(self, binary_info: NativeBinaryInfo) -> bool:
        """Check if this module should analyze the given binary"""
        # Only analyze .so files
        return (super().can_analyze(binary_info) and 
                binary_info.file_name.endswith('.so') and
                binary_info.file_size > 0)
    
    def get_module_name(self) -> str:
        """Get the module name"""
        return "native_string_extraction"