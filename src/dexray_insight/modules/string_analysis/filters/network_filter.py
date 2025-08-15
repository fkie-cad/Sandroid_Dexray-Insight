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
            # Pre-filter obvious non-IP strings
            if self._contains_invalid_ip_characters(string):
                continue
                
            if self._is_valid_ipv4(string):
                ip_addresses.append(string)
                self.logger.debug(f"Valid IPv4 found: {string}")
            elif self._is_valid_ipv6(string):
                ip_addresses.append(string)
                self.logger.debug(f"Valid IPv6 found: {string}")
        
        self.logger.info(f"Extracted {len(ip_addresses)} valid IP addresses")
        return ip_addresses
    
    def _contains_invalid_ip_characters(self, string: str) -> bool:
        """
        Check if string contains characters that should never appear in IP addresses.
        
        Args:
            string: String to check
            
        Returns:
            True if string contains invalid IP characters
        """
        # IP addresses should only contain digits, dots, colons, and letters (for IPv6)
        # Strings like "E::TB;>" contain invalid characters for IPs
        invalid_chars = set(string) - set('0123456789.:abcdefABCDEF')
        return len(invalid_chars) > 0
    
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
            # Check if string contains multiple concatenated URLs
            if self._contains_multiple_urls(string):
                split_urls = self._split_concatenated_urls(string)
                for url in split_urls:
                    if self._is_valid_url(url):
                        urls.append(url)
                        self.logger.debug(f"Valid URL found from split: {url}")
            elif self._is_valid_url(string):
                urls.append(string)
                self.logger.debug(f"Valid URL found: {string}")
        
        self.logger.info(f"Extracted {len(urls)} valid URLs")
        return urls
    
    def _contains_multiple_urls(self, string: str) -> bool:
        """
        Check if string contains multiple concatenated URLs.
        
        Args:
            string: String to check
            
        Returns:
            True if string contains multiple URLs
        """
        # Look for patterns like "https://....,https://..." or "http://...,https://..."
        url_count = string.count('://') 
        return url_count > 1
    
    def _split_concatenated_urls(self, string: str) -> List[str]:
        """
        Split concatenated URLs into individual URLs.
        
        Args:
            string: String containing multiple URLs
            
        Returns:
            List of individual URLs
        """
        urls = []
        
        # Split by common separators
        separators = [',', ';', ' ', '|']
        
        # Start with the original string
        parts = [string]
        
        # Split by each separator
        for separator in separators:
            new_parts = []
            for part in parts:
                new_parts.extend(part.split(separator))
            parts = new_parts
        
        # Filter parts that look like URLs
        for part in parts:
            part = part.strip()
            if part and ('://' in part):
                urls.append(part)
        
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
        
        # Filter out common false positives that look like IPs but are version numbers
        if self._is_likely_version_number(ip):
            return False
        
        # Additional validation - check octets are in valid range
        try:
            octets = [int(octet) for octet in ip.split('.')]
            return all(0 <= octet <= 255 for octet in octets)
        except (ValueError, AttributeError):
            return False
    
    def _is_likely_version_number(self, ip: str) -> bool:
        """
        Check if an IP-like string is likely a version number.
        
        Args:
            ip: String that matches IP pattern
            
        Returns:
            True if likely a version number, not an IP
        """
        parts = ip.split('.')
        
        # Allow known valid IP addresses
        if ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.1.1", "8.8.8.8", "1.1.1.1"]:
            return False
        
        # Allow common private IP ranges (these are valid IPs)
        if ip.startswith(("192.168.", "10.0.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.")):
            return False
        
        try:
            nums = [int(part) for part in parts]
            
            # If it has more than 4 octets, it's definitely a version (e.g., "5.9.0.4.0")
            if len(nums) > 4:
                return True
            
            # Common version patterns for 4-octet versions:
            if len(nums) == 4:
                major, minor, patch, build = nums
                
                # Very common version patterns like x.y.0.0 or x.0.0.0
                if patch == 0 and build == 0:
                    return True
                    
                # Pattern like 16.7.21.0 (double digit.single.double.zero) - common in software versions
                if major >= 10 and minor < 10 and patch >= 10 and build == 0:
                    return True
                
                # Patterns like 6.17.0.0, 4.7.0.0 (single.double.zero.zero)
                if major < 10 and minor > 10 and patch == 0 and build == 0:
                    return True
                
                # Pattern like 7.3.1.0, 12.4.2.0 (x.y.z.0) ending in zero
                if build == 0 and major < 50 and minor < 50 and patch < 50:
                    return True
                
                # Pattern like 5.9.0.4 (x.y.0.z) with zero in third position
                if patch == 0 and major < 50 and minor < 50 and build < 50:
                    return True
            
            # Common 3-octet version patterns
            if len(nums) == 3:
                major, minor, patch = nums
                
                # Patterns like x.y.0 are often versions, but be careful with IPs
                # Only flag as version if major version is reasonable for software
                if patch == 0 and major < 50:
                    return True
                    
                # Software version patterns with larger numbers
                if major > 50 or minor > 50:
                    return True
                    
            return False
            
        except ValueError:
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
        
        # Filter out placeholder and example URLs
        if self._is_placeholder_url(url):
            return False
        
        # Filter out XML namespaces that look like URLs
        if self._is_xml_namespace(url):
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
    
    def _is_placeholder_url(self, url: str) -> bool:
        """
        Check if URL is a placeholder or example URL.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is a placeholder
        """
        url_lower = url.lower()
        
        # Common placeholder domains
        placeholder_domains = [
            'example.com', 'example.org', 'example.net',
            'test.com', 'test.org', 'localhost',
            'placeholder.com', 'dummy.com', 'fake.com'
        ]
        
        for domain in placeholder_domains:
            if domain in url_lower:
                return True
        
        return False
    
    def _is_xml_namespace(self, url: str) -> bool:
        """
        Check if URL is actually an XML namespace.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is an XML namespace
        """
        url_lower = url.lower()
        
        # Common XML namespace patterns
        xml_namespace_patterns = [
            'schemas.android.com',
            'www.w3.org/ns/',
            'www.w3.org/1999/',
            'www.w3.org/2000/',
            'www.w3.org/2001/',
            'schemas.xmlsoap.org',
            'schemas.microsoft.com',
            'ns.adobe.com'
        ]
        
        for pattern in xml_namespace_patterns:
            if pattern in url_lower:
                return True
        
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