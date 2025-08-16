#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Version Parser for CVE Scanning

This module provides utilities for parsing, normalizing, and comparing
software version strings in the context of CVE vulnerability checking.
"""

import re
from typing import Optional, Tuple
import logging


class VersionParser:
    """Utility class for parsing and comparing version strings"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common version patterns
        self.version_patterns = [
            # Standard semantic versioning (1.2.3, 1.2.3-alpha, 1.2.3+build)
            r'^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9\-\.]+))?(?:\+([a-zA-Z0-9\-\.]+))?$',
            
            # Two-part versions (1.2, 1.2-alpha)
            r'^(\d+)\.(\d+)(?:-([a-zA-Z0-9\-\.]+))?(?:\+([a-zA-Z0-9\-\.]+))?$',
            
            # Single number versions (1, 2)
            r'^(\d+)(?:-([a-zA-Z0-9\-\.]+))?(?:\+([a-zA-Z0-9\-\.]+))?$',
            
            # Four-part versions common in Android (1.2.3.4)
            r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$',
            
            # Date-based versions (20210101, 2021.01.01)
            r'^(\d{4})\.?(\d{2})\.?(\d{2})(?:\.(\d+))?$'
        ]
    
    def parse_version(self, version_str: str) -> Optional[Tuple]:
        """
        Parse a version string into components.
        
        Args:
            version_str: Version string to parse
            
        Returns:
            Tuple of version components or None if parsing fails
        """
        if not version_str:
            return None
        
        # Clean up the version string
        cleaned = self._clean_version_string(version_str)
        
        for pattern in self.version_patterns:
            match = re.match(pattern, cleaned, re.IGNORECASE)
            if match:
                return match.groups()
        
        # If no pattern matches, try to extract numbers
        numbers = re.findall(r'\d+', cleaned)
        if numbers:
            return tuple(numbers)
        
        self.logger.debug(f"Could not parse version: {version_str}")
        return None
    
    def _clean_version_string(self, version: str) -> str:
        """Clean and normalize version string"""
        # Remove common prefixes
        cleaned = re.sub(r'^[vV]', '', version.strip())
        
        # Remove common suffixes that don't affect version comparison
        cleaned = re.sub(r'\s*\(.*\)$', '', cleaned)  # Remove parenthetical notes
        cleaned = re.sub(r'\s*-SNAPSHOT$', '', cleaned, re.IGNORECASE)  # Remove Maven SNAPSHOT
        
        return cleaned
    
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
        try:
            # Try using packaging library for proper version comparison
            from packaging import version as pkg_version
            v1 = pkg_version.parse(version1)
            v2 = pkg_version.parse(version2)
            
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0
                
        except Exception:
            # Fallback to custom comparison
            return self._custom_version_compare(version1, version2)
    
    def _custom_version_compare(self, version1: str, version2: str) -> int:
        """Custom version comparison when packaging library is not available"""
        parts1 = self.parse_version(version1)
        parts2 = self.parse_version(version2)
        
        if parts1 is None and parts2 is None:
            return 0
        elif parts1 is None:
            return -1
        elif parts2 is None:
            return 1
        
        # Convert to integers for numeric comparison
        nums1 = []
        nums2 = []
        
        for part in parts1:
            if part and part.isdigit():
                nums1.append(int(part))
            elif part:
                # Handle pre-release versions (alpha, beta, rc)
                nums1.append(self._prerelease_value(part))
        
        for part in parts2:
            if part and part.isdigit():
                nums2.append(int(part))
            elif part:
                nums2.append(self._prerelease_value(part))
        
        # Pad shorter version with zeros
        max_len = max(len(nums1), len(nums2))
        nums1.extend([0] * (max_len - len(nums1)))
        nums2.extend([0] * (max_len - len(nums2)))
        
        # Compare component by component
        for i in range(max_len):
            if nums1[i] < nums2[i]:
                return -1
            elif nums1[i] > nums2[i]:
                return 1
        
        return 0
    
    def _prerelease_value(self, prerelease: str) -> int:
        """Convert pre-release string to numeric value for comparison"""
        prerelease_lower = prerelease.lower()
        
        if 'alpha' in prerelease_lower:
            return -1000
        elif 'beta' in prerelease_lower:
            return -500
        elif 'rc' in prerelease_lower or 'release' in prerelease_lower:
            return -100
        else:
            # Unknown pre-release, treat as less than release
            return -50
    
    def is_version_in_range(self, version: str, min_version: Optional[str] = None, 
                          max_version: Optional[str] = None, 
                          max_inclusive: bool = False) -> bool:
        """
        Check if version falls within a specified range.
        
        Args:
            version: Version to check
            min_version: Minimum version (inclusive)
            max_version: Maximum version 
            max_inclusive: Whether max_version is inclusive
            
        Returns:
            True if version is in range
        """
        if min_version:
            if self.compare_versions(version, min_version) < 0:
                return False
        
        if max_version:
            comparison = self.compare_versions(version, max_version)
            if max_inclusive and comparison > 0:
                return False
            elif not max_inclusive and comparison >= 0:
                return False
        
        return True
    
    def normalize_version(self, version: str) -> str:
        """
        Normalize version string to a standard format.
        
        Args:
            version: Version string to normalize
            
        Returns:
            Normalized version string
        """
        parsed = self.parse_version(version)
        if not parsed:
            return version
        
        # Take only numeric parts and join with dots
        numeric_parts = []
        for part in parsed:
            if part and part.isdigit():
                numeric_parts.append(part)
            elif part:
                # For non-numeric parts, add as-is
                numeric_parts.append(part)
        
        return '.'.join(numeric_parts[:4])  # Limit to 4 parts max
    
    def extract_version_from_string(self, text: str) -> Optional[str]:
        """
        Extract version string from text that may contain additional information.
        
        Args:
            text: Text that may contain a version
            
        Returns:
            Extracted version string or None
        """
        # Common version patterns in text
        patterns = [
            r'[vV]?(\d+\.\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9\-\.]+)?)',
            r'[vV]?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9\-\.]+)?)',
            r'[vV]?(\d+(?:\.\d+)*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        
        return None