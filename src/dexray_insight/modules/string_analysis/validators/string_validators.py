#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
String Validators for String Analysis

Common validation utilities for string pattern validation and format checking.
Provides shared validation logic used across different filter components.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import re
import logging
from typing import List, Dict, Any
from urllib.parse import urlparse


class StringValidators:
    """
    Common validation utilities for string pattern validation.
    
    Single Responsibility: Provide shared validation logic and
    configuration validation for string analysis components.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    @staticmethod
    def validate_email_format(email: str) -> bool:
        """
        Validate basic email format.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email has valid basic format
        """
        if not email or '@' not in email:
            return False
        
        # Basic pattern check
        email_pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        return bool(email_pattern.match(email))
    
    @staticmethod
    def validate_ipv4_format(ip: str) -> bool:
        """
        Validate IPv4 address format.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if IP has valid IPv4 format
        """
        if not ip:
            return False
        
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if not (0 <= num <= 255):
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def validate_url_format(url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL has valid format
        """
        if not url:
            return False
        
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    @staticmethod
    def validate_domain_format(domain: str) -> bool:
        """
        Validate basic domain format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if domain has valid basic format
        """
        if not domain or ' ' in domain:
            return False
        
        # Must have at least one dot and reasonable length
        if '.' not in domain or len(domain) < 3 or len(domain) > 253:
            return False
        
        # Basic pattern check
        domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(domain_pattern.match(domain))
    
    @staticmethod
    def validate_regex_pattern(pattern: str) -> bool:
        """
        Validate if a string is a valid regex pattern.
        
        Args:
            pattern: Regex pattern to validate
            
        Returns:
            True if pattern is valid regex
        """
        if not pattern:
            return False
        
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False
    
    @staticmethod
    def validate_string_length(string: str, min_length: int = 1, max_length: int = 1000) -> bool:
        """
        Validate string length within specified bounds.
        
        Args:
            string: String to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length
            
        Returns:
            True if string length is within bounds
        """
        if not isinstance(string, str):
            return False
        
        return min_length <= len(string) <= max_length
    
    def validate_filter_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate configuration for string analysis filters.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate minimum string length
        min_length = config.get('min_string_length', 3)
        if not isinstance(min_length, int) or min_length < 1:
            errors.append("min_string_length must be an integer >= 1")
        
        # Validate exclude patterns
        exclude_patterns = config.get('exclude_patterns', [])
        if not isinstance(exclude_patterns, list):
            errors.append("exclude_patterns must be a list")
        else:
            for i, pattern in enumerate(exclude_patterns):
                if not isinstance(pattern, str):
                    errors.append(f"exclude_patterns[{i}] must be a string")
                elif not self.validate_regex_pattern(pattern):
                    errors.append(f"exclude_patterns[{i}] is not a valid regex pattern: '{pattern}'")
        
        # Validate pattern flags
        patterns = config.get('patterns', {})
        if patterns and not isinstance(patterns, dict):
            errors.append("patterns must be a dictionary")
        else:
            for pattern_type, enabled in patterns.items():
                if not isinstance(enabled, bool):
                    errors.append(f"patterns['{pattern_type}'] must be a boolean")
        
        return errors
    
    def validate_extractor_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate configuration for string extractor.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate minimum string length
        min_length = config.get('min_string_length', 3)
        if not isinstance(min_length, int) or min_length < 1:
            errors.append("min_string_length must be an integer >= 1")
        
        # Validate exclude patterns
        exclude_patterns = config.get('exclude_patterns', [])
        if not isinstance(exclude_patterns, list):
            errors.append("exclude_patterns must be a list")
        else:
            for i, pattern in enumerate(exclude_patterns):
                if not isinstance(pattern, str):
                    errors.append(f"exclude_patterns[{i}] must be a string")
                elif not self.validate_regex_pattern(pattern):
                    errors.append(f"exclude_patterns[{i}] is not a valid regex pattern: '{pattern}'")
        
        return errors
    
    @staticmethod
    def sanitize_string_for_logging(string: str, max_length: int = 100) -> str:
        """
        Sanitize a string for safe logging by truncating and escaping.
        
        Args:
            string: String to sanitize
            max_length: Maximum length for truncation
            
        Returns:
            Sanitized string safe for logging
        """
        if not isinstance(string, str):
            return str(string)
        
        # Truncate if too long
        if len(string) > max_length:
            string = string[:max_length] + "..."
        
        # Replace potentially problematic characters
        sanitized = string.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        
        return sanitized
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """
        Normalize domain name for consistent processing.
        
        Args:
            domain: Domain name to normalize
            
        Returns:
            Normalized domain name (lowercase, trimmed)
        """
        if not isinstance(domain, str):
            return ""
        
        return domain.strip().lower()
    
    @staticmethod
    def extract_file_extension(filename: str) -> str:
        """
        Extract file extension from filename.
        
        Args:
            filename: Filename to extract extension from
            
        Returns:
            File extension (with dot) or empty string if no extension
        """
        if not isinstance(filename, str) or '.' not in filename:
            return ""
        
        return '.' + filename.split('.')[-1].lower()
    
    def get_validation_report(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive validation report for configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            Dictionary with validation results
        """
        report = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'config_summary': {}
        }
        
        # Validate filter config
        filter_errors = self.validate_filter_config(config)
        report['errors'].extend(filter_errors)
        
        # Validate extractor config  
        extractor_errors = self.validate_extractor_config(config)
        report['errors'].extend(extractor_errors)
        
        # Generate warnings for suboptimal settings
        min_length = config.get('min_string_length', 3)
        if min_length > 10:
            report['warnings'].append(f"min_string_length ({min_length}) is quite high and may filter out valid short strings")
        
        exclude_patterns = config.get('exclude_patterns', [])
        if len(exclude_patterns) > 20:
            report['warnings'].append(f"Large number of exclude patterns ({len(exclude_patterns)}) may impact performance")
        
        # Summary
        report['config_summary'] = {
            'min_string_length': min_length,
            'exclude_patterns_count': len(exclude_patterns),
            'patterns_enabled': sum(1 for enabled in config.get('patterns', {}).values() if enabled)
        }
        
        report['valid'] = len(report['errors']) == 0
        
        return report