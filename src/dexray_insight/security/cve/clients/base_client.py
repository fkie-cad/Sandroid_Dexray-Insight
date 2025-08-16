#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base CVE Client

This module provides the abstract base class for CVE database clients.
All specific CVE clients should inherit from this base class.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import requests
import logging
from ..models.vulnerability import CVEVulnerability
from ..utils.rate_limiter import APIRateLimiter, RateLimitConfig
from ..utils.cache_manager import CVECacheManager


class BaseCVEClient(ABC):
    """Abstract base class for CVE database clients"""
    
    def __init__(self, 
                 api_key: Optional[str] = None,
                 timeout: int = 10,
                 rate_limiter: Optional[APIRateLimiter] = None,
                 cache_manager: Optional[CVECacheManager] = None):
        """
        Initialize CVE client.
        
        Args:
            api_key: API key for the CVE database (if required)
            timeout: Request timeout in seconds
            rate_limiter: Rate limiter instance
            cache_manager: Cache manager instance
        """
        self.api_key = api_key
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Set up rate limiter with default config if not provided
        if rate_limiter is None:
            rate_config = self._get_default_rate_limit_config()
            self.rate_limiter = APIRateLimiter(rate_config)
        else:
            self.rate_limiter = rate_limiter
        
        self.cache_manager = cache_manager
        
        # HTTP session for connection pooling
        self.session = requests.Session()
        self.session.timeout = timeout
        
        # Set up default headers
        self._setup_headers()
    
    @abstractmethod
    def _get_default_rate_limit_config(self) -> RateLimitConfig:
        """Get default rate limit configuration for this client"""
        pass
    
    @abstractmethod
    def _setup_headers(self):
        """Set up HTTP headers for API requests"""
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Get the name of this CVE source"""
        pass
    
    @abstractmethod
    def search_vulnerabilities(self, library_name: str, version: Optional[str] = None) -> List[CVEVulnerability]:
        """
        Search for vulnerabilities affecting a library.
        
        Args:
            library_name: Name of the library
            version: Specific version to check (optional)
            
        Returns:
            List of CVE vulnerabilities
        """
        pass
    
    def search_vulnerabilities_with_cache(self, library_name: str, version: Optional[str] = None) -> List[CVEVulnerability]:
        """
        Search for vulnerabilities with caching support.
        
        Args:
            library_name: Name of the library
            version: Specific version to check (optional)
            
        Returns:
            List of CVE vulnerabilities
        """
        # Check cache first if cache manager is available
        if self.cache_manager and version:
            cached_result = self.cache_manager.get_cached_result(
                library_name, version, self.get_source_name()
            )
            if cached_result is not None:
                self.logger.debug(f"Using cached results for {library_name}:{version}")
                return [self._dict_to_vulnerability(vuln_dict) for vuln_dict in cached_result]
        
        # Rate limit check
        wait_time = self.rate_limiter.wait_for_request()
        if wait_time > 0:
            self.logger.info(f"Rate limited, waited {wait_time:.2f} seconds")
        
        try:
            # Make the actual API request
            vulnerabilities = self.search_vulnerabilities(library_name, version)
            
            # Record the request
            self.rate_limiter.record_request()
            
            # Cache the result if cache manager is available
            if self.cache_manager and version:
                vuln_dicts = [vuln.to_dict() for vuln in vulnerabilities]
                self.cache_manager.cache_result(
                    library_name, version, self.get_source_name(), vuln_dicts
                )
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error searching vulnerabilities for {library_name}: {e}")
            return []
    
    def _make_request(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make HTTP request with error handling.
        
        Args:
            url: URL to request
            params: Query parameters
            
        Returns:
            JSON response data
            
        Raises:
            requests.exceptions.RequestException: On request errors
        """
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout for {url}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error for {url}: {e}")
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error for {url}: {e}")
            raise
        except ValueError as e:
            self.logger.error(f"JSON decode error for {url}: {e}")
            raise
    
    def _dict_to_vulnerability(self, vuln_dict: Dict[str, Any]) -> CVEVulnerability:
        """
        Convert dictionary to CVEVulnerability object.
        
        Args:
            vuln_dict: Vulnerability dictionary
            
        Returns:
            CVEVulnerability object
        """
        # This is a simplified conversion - subclasses should override
        # for more sophisticated parsing of their specific data formats
        from ..models.vulnerability import CVESeverity
        from datetime import datetime
        
        severity = CVESeverity.UNKNOWN
        if 'severity' in vuln_dict:
            try:
                severity = CVESeverity(vuln_dict['severity'])
            except ValueError:
                pass
        
        published_date = None
        if 'published_date' in vuln_dict and vuln_dict['published_date']:
            try:
                published_date = datetime.fromisoformat(vuln_dict['published_date'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        return CVEVulnerability(
            cve_id=vuln_dict.get('cve_id', ''),
            summary=vuln_dict.get('summary', ''),
            description=vuln_dict.get('description'),
            severity=severity,
            cvss_score=vuln_dict.get('cvss_score'),
            cvss_vector=vuln_dict.get('cvss_vector'),
            published_date=published_date,
            references=vuln_dict.get('references', []),
            source=self.get_source_name(),
            raw_data=vuln_dict
        )
    
    def health_check(self) -> bool:
        """
        Check if the CVE service is available.
        
        Returns:
            True if service is healthy, False otherwise
        """
        try:
            # Subclasses should implement specific health checks
            return True
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get current rate limit status"""
        return self.rate_limiter.get_rate_limit_status()
    
    def __del__(self):
        """Clean up resources"""
        if hasattr(self, 'session'):
            self.session.close()