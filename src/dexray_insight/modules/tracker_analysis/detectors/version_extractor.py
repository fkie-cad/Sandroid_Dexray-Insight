#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Version Extractor for Tracker Analysis

Specialized extractor for version information from tracker pattern matches.
Uses both specific version patterns and fallback patterns for version detection.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

import re
import logging
from typing import List, Optional


class VersionExtractor:
    """
    Specialized extractor for tracker version information.
    
    Single Responsibility: Extract version information from matched strings
    using specific patterns and common fallback patterns.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common fallback version patterns
        self.fallback_patterns = [
            r'(\d+\.\d+\.\d+)',  # Standard semantic versioning
            r'v(\d+\.\d+\.\d+)',  # Version with v prefix
            r'(\d+\.\d+)',        # Major.minor versioning
        ]
    
    def extract_version(self, matches: List[str], version_patterns: List[str]) -> Optional[str]:
        """
        Extract version information from matched strings.
        
        Args:
            matches: List of strings that matched tracker patterns
            version_patterns: Specific version patterns for this tracker
            
        Returns:
            Extracted version string or None if no version found
        """
        # First try specific version patterns for this tracker
        version = self._extract_with_patterns(matches, version_patterns)
        if version:
            return version
        
        # Fallback to common version patterns
        version = self._extract_with_patterns(matches, self.fallback_patterns)
        return version
    
    def _extract_with_patterns(self, matches: List[str], patterns: List[str]) -> Optional[str]:
        """
        Extract version using a specific set of patterns.
        
        Args:
            matches: List of strings to search in
            patterns: List of regex patterns to try
            
        Returns:
            First version found or None
        """
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for match in matches:
                    version_match = regex.search(match)
                    if version_match:
                        version = version_match.group(1)
                        self.logger.debug(f"Extracted version '{version}' using pattern '{pattern}' from '{match}'")
                        return version
            except (re.error, IndexError) as e:
                self.logger.debug(f"Pattern '{pattern}' failed: {str(e)}")
                continue
        
        return None
    
    def extract_version_from_filename(self, filename: str) -> Optional[str]:
        """
        Extract version information from a filename.
        
        Args:
            filename: Filename to extract version from
            
        Returns:
            Extracted version string or None
        """
        # Patterns specific to filenames
        filename_patterns = [
            r'(\d+\.\d+\.\d+)',  # Standard semantic versioning
            r'v(\d+\.\d+\.\d+)',  # Version with v prefix
            r'-(\d+\.\d+\.\d+)',  # Version with dash prefix
            r'_(\d+\.\d+\.\d+)',  # Version with underscore prefix
            r'(\d+\.\d+)',        # Major.minor versioning
        ]
        
        return self._extract_with_patterns([filename], filename_patterns)
    
    def validate_version_format(self, version: str) -> bool:
        """
        Validate if a version string follows common versioning patterns.
        
        Args:
            version: Version string to validate
            
        Returns:
            True if version format is valid
        """
        if not version:
            return False
        
        # Common version format patterns
        valid_patterns = [
            r'^\d+\.\d+\.\d+$',      # Semantic versioning (1.2.3)
            r'^\d+\.\d+$',           # Major.minor (1.2)
            r'^\d+\.\d+\.\d+\.\d+$', # Extended versioning (1.2.3.4)
            r'^\d+$',                # Single number (1)
        ]
        
        for pattern in valid_patterns:
            try:
                if re.match(pattern, version.strip()):
                    return True
            except re.error:
                continue
        
        return False
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        
        Args:
            version1: First version string
            version2: Second version string
            
        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        if not version1 and not version2:
            return 0
        if not version1:
            return -1
        if not version2:
            return 1
        
        try:
            # Convert version strings to lists of integers for comparison
            v1_parts = [int(x) for x in version1.split('.') if x.isdigit()]
            v2_parts = [int(x) for x in version2.split('.') if x.isdigit()]
            
            # Pad shorter version with zeros
            max_length = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_length - len(v1_parts)))
            v2_parts.extend([0] * (max_length - len(v2_parts)))
            
            for v1_part, v2_part in zip(v1_parts, v2_parts):
                if v1_part < v2_part:
                    return -1
                elif v1_part > v2_part:
                    return 1
            
            return 0
        
        except (ValueError, AttributeError):
            # Fallback to string comparison if numeric comparison fails
            return -1 if version1 < version2 else (1 if version1 > version2 else 0)