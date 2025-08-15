#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
String Extractor for String Analysis

Specialized extractor for collecting strings from various APK components
including DEX files, native analysis results, and .NET analysis results.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import logging
import re
from typing import Set
from dexray_insight.core.base_classes import AnalysisContext


class StringExtractor:
    """
    Specialized extractor for string collection from APK components.
    
    Single Responsibility: Extract and filter strings from various
    APK sources with configurable filtering options.
    """
    
    def __init__(self, config: dict = None):
        self.logger = logging.getLogger(__name__)
        if config is None:
            config = {}
        
        # Configuration options
        self.min_string_length = config.get('min_string_length', 3)
        self.exclude_patterns = config.get('exclude_patterns', [])
        
    def extract_all_strings(self, context: AnalysisContext) -> Set[str]:
        """
        Extract all strings from available analysis sources.
        
        Args:
            context: Analysis context with various module results
            
        Returns:
            Set of filtered strings from all available sources
        """
        strings_set = set()
        
        # Add pre-found strings from .NET analysis
        dotnet_strings = self._extract_dotnet_strings(context)
        if dotnet_strings:
            self.logger.debug(f"Adding {len(dotnet_strings)} strings from .NET analysis")
            strings_set.update(dotnet_strings)
        
        # Add native strings from native analysis
        native_strings = self._extract_native_strings(context)
        if native_strings:
            self.logger.debug(f"Adding {len(native_strings)} strings from native analysis")
            strings_set.update(native_strings)
        
        # Extract strings from DEX files
        dex_strings = self._extract_dex_strings(context)
        if dex_strings:
            self.logger.debug(f"Adding {len(dex_strings)} strings from DEX analysis")
            strings_set.update(dex_strings)
        
        # Extract strings from XML resources (strings.xml, etc.)
        xml_strings = self._extract_xml_strings(context)
        if xml_strings:
            self.logger.debug(f"Adding {len(xml_strings)} strings from XML resources")
            strings_set.update(xml_strings)
        
        self.logger.info(f"Total strings extracted from all sources: {len(strings_set)}")
        return strings_set
    
    def _extract_dotnet_strings(self, context: AnalysisContext) -> Set[str]:
        """
        Extract strings from .NET analysis results.
        
        Args:
            context: Analysis context
            
        Returns:
            Set of strings from .NET analysis
        """
        strings_set = set()
        
        try:
            dotnet_result = context.get_result('dotnet_analysis')
            if dotnet_result and isinstance(dotnet_result, list):
                strings_set.update(dotnet_result)
                self.logger.debug(f"Found {len(dotnet_result)} strings from .NET analysis")
        except Exception as e:
            self.logger.debug(f"Error extracting .NET strings: {str(e)}")
            
        return strings_set
    
    def _extract_native_strings(self, context: AnalysisContext) -> Set[str]:
        """
        Extract strings from native analysis results.
        
        Args:
            context: Analysis context
            
        Returns:
            Set of strings from native analysis
        """
        strings_set = set()
        
        try:
            native_strings = context.module_results.get('native_strings', [])
            if native_strings:
                strings_set.update(native_strings)
                self.logger.debug(f"Found {len(native_strings)} strings from native analysis")
        except Exception as e:
            self.logger.debug(f"Error extracting native strings: {str(e)}")
            
        return strings_set
    
    def _extract_dex_strings(self, context: AnalysisContext) -> Set[str]:
        """
        Extract strings from DEX files using androguard.
        
        Args:
            context: Analysis context with androguard object
            
        Returns:
            Set of filtered strings from DEX files
        """
        strings_set = set()
        
        if not context.androguard_obj:
            self.logger.warning("No androguard object available in context")
            return strings_set
        
        try:
            dex_obj = context.androguard_obj.get_androguard_dex()
            self.logger.debug(f"Found {len(dex_obj) if dex_obj else 0} DEX objects in binary")
            
            if not dex_obj:
                self.logger.warning("No DEX objects returned from androguard")
                return strings_set
            
            total_raw_strings = 0
            filtered_by_length = 0
            filtered_by_exclude = 0
            
            for i, dex in enumerate(dex_obj):
                dex_strings = dex.get_strings()
                total_raw_strings += len(dex_strings)
                self.logger.debug(f"DEX {i+1}/{len(dex_obj)}: Processing {len(dex_strings)} raw strings")
                
                for string in dex_strings:
                    string_val = str(string)
                    
                    # Apply length filter
                    if len(string_val) < self.min_string_length:
                        filtered_by_length += 1
                        continue
                    
                    # Apply exclude patterns filter
                    if self._should_exclude_string(string_val):
                        filtered_by_exclude += 1
                        continue
                    
                    strings_set.add(string_val)
            
            # Log comprehensive statistics
            self._log_extraction_stats(total_raw_strings, filtered_by_length,
                                       filtered_by_exclude, len(strings_set))
                
        except Exception as e:
            self.logger.error(f"Error extracting strings from DEX: {str(e)}")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
        
        return strings_set
    
    def _extract_xml_strings(self, context: AnalysisContext) -> Set[str]:
        """
        Extract strings from XML resources using androguard APK object.
        
        This method extracts strings from XML resources like strings.xml, which often
        contain API keys, configuration values, and other sensitive data that should
        be analyzed for security vulnerabilities.
        
        Args:
            context: Analysis context with androguard object
            
        Returns:
            Set of filtered strings from XML resources
        """
        strings_set = set()
        
        if not context.androguard_obj:
            self.logger.warning("No androguard object available in context for XML extraction")
            return strings_set
        
        try:
            apk_obj = context.androguard_obj.get_androguard_apk()
            if not apk_obj:
                self.logger.warning("No APK object returned from androguard")
                return strings_set
            
            total_raw_strings = 0
            filtered_by_length = 0
            filtered_by_exclude = 0
            
            # Get all resource files, focusing on XML files
            resources = apk_obj.get_files_types()
            xml_files = resources.get('XML', [])
            
            self.logger.debug(f"Found {len(xml_files)} XML files in APK for string extraction")
            
            # Extract from strings.xml and other string resource files
            for xml_file in xml_files:
                try:
                    # Focus on string resource files
                    if 'strings.xml' in xml_file or 'res/values' in xml_file:
                        self.logger.debug(f"Processing XML resource file: {xml_file}")
                        
                        # Get XML content
                        xml_content = apk_obj.get_file(xml_file)
                        if xml_content:
                            # Parse XML and extract string values
                            xml_strings = self._parse_xml_for_strings(xml_content, xml_file)
                            total_raw_strings += len(xml_strings)
                            
                            for string_val in xml_strings:
                                # Apply length filter
                                if len(string_val) < self.min_string_length:
                                    filtered_by_length += 1
                                    continue
                                
                                # Apply exclude patterns filter
                                if self._should_exclude_string(string_val):
                                    filtered_by_exclude += 1
                                    continue
                                
                                strings_set.add(string_val)
                
                except Exception as e:
                    self.logger.warning(f"Error processing XML file {xml_file}: {str(e)}")
                    continue
            
            # Also extract from the Android manifest and other APK resources
            try:
                manifest_strings = self._extract_manifest_strings(apk_obj)
                total_raw_strings += len(manifest_strings)
                
                for string_val in manifest_strings:
                    # Apply length filter
                    if len(string_val) < self.min_string_length:
                        filtered_by_length += 1
                        continue
                    
                    # Apply exclude patterns filter  
                    if self._should_exclude_string(string_val):
                        filtered_by_exclude += 1
                        continue
                    
                    strings_set.add(string_val)
                    
            except Exception as e:
                self.logger.warning(f"Error extracting manifest strings: {str(e)}")
            
            # Log comprehensive statistics
            self._log_extraction_stats(total_raw_strings, filtered_by_length,
                                       filtered_by_exclude, len(strings_set))
                
        except Exception as e:
            self.logger.error(f"Error extracting strings from XML resources: {str(e)}")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
        
        return strings_set
    
    def _parse_xml_for_strings(self, xml_content: bytes, xml_file: str) -> Set[str]:
        """
        Parse XML content to extract string values.
        
        Args:
            xml_content: Raw XML content as bytes
            xml_file: XML file path for logging
            
        Returns:
            Set of string values found in XML
        """
        strings_set = set()
        
        try:
            import xml.etree.ElementTree as ET
            
            # Parse XML content
            xml_text = xml_content.decode('utf-8', errors='ignore')
            root = ET.fromstring(xml_text)
            
            # Extract text content from all elements
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    strings_set.add(elem.text.strip())
                if elem.tail and elem.tail.strip():
                    strings_set.add(elem.tail.strip())
                
                # Also extract attribute values
                for attr_value in elem.attrib.values():
                    if attr_value and attr_value.strip():
                        strings_set.add(attr_value.strip())
            
            self.logger.debug(f"Extracted {len(strings_set)} strings from {xml_file}")
            
        except Exception as e:
            self.logger.warning(f"Error parsing XML file {xml_file}: {str(e)}")
            # Fallback: use regex to find potential string values
            try:
                xml_text = xml_content.decode('utf-8', errors='ignore')
                # Look for text between XML tags and in attributes
                import re
                # Find content between > and <
                tag_content = re.findall(r'>(.*?)<', xml_text)
                # Find attribute values
                attr_values = re.findall(r'="([^"]*)"', xml_text)
                
                for content in tag_content + attr_values:
                    if content and content.strip():
                        strings_set.add(content.strip())
                        
                self.logger.debug(f"Fallback extraction found {len(strings_set)} strings from {xml_file}")
                
            except Exception as fallback_e:
                self.logger.error(f"Both XML parsing and fallback failed for {xml_file}: {str(fallback_e)}")
        
        return strings_set
    
    def _extract_manifest_strings(self, apk_obj) -> Set[str]:
        """
        Extract string values from AndroidManifest.xml.
        
        Args:
            apk_obj: Androguard APK object
            
        Returns:
            Set of string values from manifest
        """
        strings_set = set()
        
        try:
            # Get manifest as XML
            manifest_xml = apk_obj.get_android_manifest_xml()
            if manifest_xml:
                # Extract strings from manifest XML elements
                for elem in manifest_xml.iter():
                    if elem.text and elem.text.strip():
                        strings_set.add(elem.text.strip())
                    
                    # Extract attribute values
                    for attr_value in elem.attrib.values():
                        if attr_value and attr_value.strip():
                            strings_set.add(attr_value.strip())
            
            self.logger.debug(f"Extracted {len(strings_set)} strings from AndroidManifest.xml")
            
        except Exception as e:
            self.logger.warning(f"Error extracting manifest strings: {str(e)}")
        
        return strings_set
    
    def _should_exclude_string(self, string_val: str) -> bool:
        """
        Check if a string should be excluded based on configured patterns.
        
        Args:
            string_val: String to check
            
        Returns:
            True if string should be excluded
        """
        if not self.exclude_patterns:
            return False
        
        try:
            return any(re.match(pattern, string_val) for pattern in self.exclude_patterns)
        except Exception as e:
            self.logger.warning(f"Error applying exclude pattern to '{string_val}': {str(e)}")
            return False
    
    def _log_extraction_stats(self, total_raw: int, filtered_length: int,
                              filtered_exclude: int, final_count: int):
        """
        Log comprehensive string extraction statistics.
        
        Args:
            total_raw: Total raw strings found
            filtered_length: Strings filtered by minimum length
            filtered_exclude: Strings filtered by exclude patterns
            final_count: Final string count after filtering
        """
        self.logger.debug("📊 STRING EXTRACTION SUMMARY:")
        self.logger.debug(f"   📁 Total raw strings in binary: {total_raw}")
        self.logger.debug(f"   📐 Filtered by min length ({self.min_string_length}): {filtered_length}")
        self.logger.debug(f"   🚫 Filtered by exclude patterns: {filtered_exclude}")
        self.logger.debug(f"   ✅ Strings remaining after filtering: {final_count}")
        
        if final_count == 0:
            self.logger.warning("⚠️  No strings remaining after filtering - filters might be too restrictive")
        elif final_count < 10:
            self.logger.warning(f"⚠️  Very few strings found ({final_count}) - this might indicate an issue")
    
    def validate_configuration(self) -> bool:
        """
        Validate extractor configuration.
        
        Returns:
            True if configuration is valid
        """
        if self.min_string_length < 1:
            self.logger.error("Minimum string length should be at least 1")
            return False
        
        # Validate exclude patterns
        for pattern in self.exclude_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid exclude pattern '{pattern}': {str(e)}")
                return False
        
        return True
