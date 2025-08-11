#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Filter for String Analysis

Specialized filter for extracting and validating network-related strings
including IP addresses (IPv4/IPv6) and URLs from string collections.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import re
import logging
from typing import List, Set, Dict
from urllib.parse import urlparse


class NetworkFilter:
    """
    Specialized filter for network-related string extraction.
    
    Single Responsibility: Extract and validate IP addresses and URLs
    with comprehensive pattern matching and validation.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # IPv4 pattern with comprehensive validation
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\b'
        )
        
        # IPv6 pattern (simplified)
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|' +
            r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|' +
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
        )
        
        # URL pattern with protocol validation
        self.url_pattern = re.compile(
            r'((?:https?|ftp):\/\/(?:www\.)?[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)'
        )
        
        # Private IP ranges for classification
        self.private_ip_ranges = [
            (r'^10\.', 'Private (Class A)'),
            (r'^172\.(?:1[6-9]|2[0-9]|3[01])\.', 'Private (Class B)'),
            (r'^192\.168\.', 'Private (Class C)'),
            (r'^127\.', 'Loopback'),
            (r'^169\.254\.', 'Link-local'),
            (r'^0\.', 'This network'),
            (r'^224\.', 'Multicast')
        ]
    
    def filter_ip_addresses(self, strings: Set[str]) -> List[str]:
        """
        Filter and validate IP addresses from string collection.
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of valid IP addresses
        """
        ip_addresses = []
        
        for string in strings:
            if self._is_valid_ipv4(string):
                ip_addresses.append(string)
                self.logger.debug(f"Valid IPv4 found: {string}")
            elif self._is_valid_ipv6(string):
                ip_addresses.append(string)
                self.logger.debug(f"Valid IPv6 found: {string}")
        
        self.logger.info(f"Extracted {len(ip_addresses)} valid IP addresses")
        return ip_addresses
    
    def filter_urls(self, strings: Set[str]) -> List[str]:
        """
        Filter and validate URLs from string collection.
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of valid URLs
        """
        urls = []
        
        for string in strings:
            if self._is_valid_url(string):
                urls.append(string)
                self.logger.debug(f"Valid URL found: {string}")
        
        self.logger.info(f"Extracted {len(urls)} valid URLs")
        return urls
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """
        Validate IPv4 address format and ranges.
        
        Args:
            ip: String to validate as IPv4
            
        Returns:
            True if valid IPv4 address
        """
        if not self.ipv4_pattern.match(ip):
            return False
        
        # Additional validation - check octets are in valid range
        try:
            octets = [int(octet) for octet in ip.split('.')]
            return all(0 <= octet <= 255 for octet in octets)
        except (ValueError, AttributeError):
            return False
    
    def _is_valid_ipv6(self, ip: str) -> bool:
        """
        Validate IPv6 address format.
        
        Args:
            ip: String to validate as IPv6
            
        Returns:
            True if valid IPv6 address
        """
        return bool(self.ipv6_pattern.match(ip))
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and structure.
        
        Args:
            url: String to validate as URL
            
        Returns:
            True if valid URL
        """
        if not self.url_pattern.match(url):
            return False
        
        try:
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Scheme must be supported
            if parsed.scheme.lower() not in ['http', 'https', 'ftp']:
                return False
            
            # Netloc should contain at least one dot (domain)
            if '.' not in parsed.netloc:
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"URL validation error for '{url}': {str(e)}")
            return False
    
    def classify_ip_addresses(self, ip_addresses: List[str]) -> Dict[str, List[str]]:
        """
        Classify IP addresses by type (private, public, etc.).
        
        Args:
            ip_addresses: List of IP addresses to classify
            
        Returns:
            Dictionary mapping IP types to lists of IPs
        """
        classified = {
            'Public IPv4': [],
            'Private IPv4': [],
            'Loopback': [],
            'Link-local': [],
            'Multicast': [],
            'IPv6': [],
            'Other': []
        }
        
        for ip in ip_addresses:
            if self._is_valid_ipv6(ip):
                classified['IPv6'].append(ip)
                continue
            
            # Classify IPv4 addresses
            ip_type = self._classify_ipv4(ip)
            if ip_type == 'Public':
                classified['Public IPv4'].append(ip)
            elif ip_type.startswith('Private'):
                classified['Private IPv4'].append(ip)
            elif ip_type == 'Loopback':
                classified['Loopback'].append(ip)
            elif ip_type == 'Link-local':
                classified['Link-local'].append(ip)
            elif ip_type == 'Multicast':
                classified['Multicast'].append(ip)
            else:
                classified['Other'].append(ip)
        
        # Remove empty categories
        return {k: v for k, v in classified.items() if v}
    
    def _classify_ipv4(self, ip: str) -> str:
        """
        Classify an IPv4 address by type.
        
        Args:
            ip: IPv4 address to classify
            
        Returns:
            Classification string
        """
        for pattern, classification in self.private_ip_ranges:
            if re.match(pattern, ip):
                return classification
        
        return 'Public'
    
    def extract_domains_from_urls(self, urls: List[str]) -> List[str]:
        """
        Extract unique domains from a list of URLs.
        
        Args:
            urls: List of URLs
            
        Returns:
            List of unique domains
        """
        domains = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    # Remove port if present
                    domain = parsed.netloc.split(':')[0].lower()
                    domains.add(domain)
            except Exception as e:
                self.logger.warning(f"Could not extract domain from URL '{url}': {str(e)}")
        
        return sorted(list(domains))
    
    def categorize_urls_by_protocol(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Group URLs by their protocol (scheme).
        
        Args:
            urls: List of URLs
            
        Returns:
            Dictionary mapping protocols to lists of URLs
        """
        categorized = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                protocol = parsed.scheme.lower()
                
                if protocol not in categorized:
                    categorized[protocol] = []
                categorized[protocol].append(url)
                
            except Exception as e:
                self.logger.warning(f"Could not categorize URL '{url}': {str(e)}")
        
        return categorized