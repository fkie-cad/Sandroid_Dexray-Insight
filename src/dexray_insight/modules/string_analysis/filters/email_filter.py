#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Email Filter for String Analysis

Specialized filter for extracting and validating email addresses from string collections.
Uses regex patterns with validation to reduce false positives.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import re
import logging
from typing import List, Set


class EmailFilter:
    """
    Specialized filter for email address extraction and validation.
    
    Single Responsibility: Extract valid email addresses from strings
    using regex patterns with comprehensive validation.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Email pattern with comprehensive matching
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        )
        
        # Additional validation patterns
        self.valid_domain_pattern = re.compile(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$')
    
    def filter_emails(self, strings: Set[str]) -> List[str]:
        """
        Filter and validate email addresses from string collection.
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of valid email addresses
        """
        emails = []
        
        for string in strings:
            if self._is_valid_email(string):
                emails.append(string)
                self.logger.debug(f"Valid email found: {string}")
        
        self.logger.info(f"Extracted {len(emails)} valid email addresses")
        return emails
    
    def _is_valid_email(self, email: str) -> bool:
        """
        Validate if a string is a properly formatted email address.
        
        Args:
            email: String to validate
            
        Returns:
            True if string is a valid email address
        """
        if not email or len(email) > 254:  # RFC 5321 limit
            return False
        
        # Basic pattern match
        if not self.email_pattern.match(email):
            return False
        
        # Split into local and domain parts
        try:
            local, domain = email.rsplit('@', 1)
        except ValueError:
            return False
        
        # Validate local part (before @)
        if not self._is_valid_local_part(local):
            return False
        
        # Validate domain part (after @)
        if not self._is_valid_domain_part(domain):
            return False
        
        return True
    
    def _is_valid_local_part(self, local: str) -> bool:
        """
        Validate the local part (before @) of an email address.
        
        Args:
            local: Local part of email address
            
        Returns:
            True if local part is valid
        """
        if not local or len(local) > 64:  # RFC 5321 limit
            return False
        
        # Check for valid characters
        if local.startswith('.') or local.endswith('.'):
            return False
        
        # Check for consecutive dots
        if '..' in local:
            return False
        
        return True
    
    def _is_valid_domain_part(self, domain: str) -> bool:
        """
        Validate the domain part (after @) of an email address.
        
        Args:
            domain: Domain part of email address
            
        Returns:
            True if domain part is valid
        """
        if not domain or len(domain) > 253:  # RFC 1035 limit
            return False
        
        # Basic domain pattern validation
        if not self.valid_domain_pattern.match(domain):
            return False
        
        # Check domain parts
        parts = domain.split('.')
        
        # Must have at least 2 parts (e.g., example.com)
        if len(parts) < 2:
            return False
        
        # Check each part
        for part in parts:
            if not part or len(part) > 63:  # RFC 1035 limit
                return False
            
            # Must start and end with alphanumeric
            if not (part[0].isalnum() and part[-1].isalnum()):
                return False
        
        # TLD should be at least 2 characters and alphabetic
        tld = parts[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False
        
        return True
    
    def get_email_domains(self, emails: List[str]) -> List[str]:
        """
        Extract unique domains from a list of email addresses.
        
        Args:
            emails: List of email addresses
            
        Returns:
            List of unique domains
        """
        domains = set()
        
        for email in emails:
            try:
                domain = email.split('@')[1]
                domains.add(domain.lower())
            except (IndexError, AttributeError):
                self.logger.warning(f"Could not extract domain from email: {email}")
        
        return sorted(list(domains))
    
    def categorize_by_domain(self, emails: List[str]) -> dict:
        """
        Group emails by their domain.
        
        Args:
            emails: List of email addresses
            
        Returns:
            Dictionary mapping domains to lists of emails
        """
        categorized = {}
        
        for email in emails:
            try:
                domain = email.split('@')[1].lower()
                if domain not in categorized:
                    categorized[domain] = []
                categorized[domain].append(email)
            except (IndexError, AttributeError):
                self.logger.warning(f"Could not categorize email: {email}")
        
        return categorized