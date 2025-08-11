#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exodus Privacy API Client

Client for fetching tracker patterns from the Exodus Privacy API.
Handles API communication, caching, and error management.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

import logging
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


class ExodusAPIClient:
    """
    Client for Exodus Privacy tracker API integration.
    
    Single Responsibility: Handle Exodus Privacy API communication,
    caching, and tracker data processing.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.api_url = config.get('exodus_api_url', 'https://reports.exodus-privacy.eu.org/api/trackers')
        self.timeout = config.get('api_timeout', 10)
        self.enabled = config.get('fetch_exodus_trackers', True)
        self._cache: Optional[List[Dict[str, Any]]] = None
        
        # Validate API URL
        if not self._validate_api_url():
            self.logger.error("Invalid Exodus API URL - disabling Exodus tracker fetching")
            self.enabled = False
    
    def _validate_api_url(self) -> bool:
        """Validate the Exodus Privacy API URL format"""
        try:
            parsed = urlparse(self.api_url)
            if not parsed.scheme or not parsed.netloc:
                return False
            return True
        except Exception:
            return False
    
    def fetch_trackers(self) -> List[Dict[str, Any]]:
        """
        Fetch tracker signatures from Exodus Privacy API.
        
        Returns:
            List of tracker dictionaries with metadata
            
        Raises:
            Exception: If API fetch fails and no cache is available
        """
        if not self.enabled:
            self.logger.debug("Exodus tracker fetching disabled")
            return []
            
        if self._cache:
            self.logger.debug("Returning cached Exodus trackers")
            return self._cache
        
        try:
            self.logger.debug(f"Fetching trackers from Exodus Privacy API: {self.api_url}")
            response = requests.get(self.api_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            trackers = []
            
            # Process the API response
            if isinstance(data, dict) and 'trackers' in data:
                for tracker_id, tracker_info in data['trackers'].items():
                    trackers.append({
                        'id': tracker_id,
                        'name': tracker_info.get('name', f'Unknown Tracker {tracker_id}'),
                        'description': tracker_info.get('description', ''),
                        'category': tracker_info.get('category', 'Unknown'),
                        'website': tracker_info.get('website', ''),
                        'code_signature': tracker_info.get('code_signature', ''),
                        'network_signature': tracker_info.get('network_signature', '')
                    })
            
            self._cache = trackers
            self.logger.info(f"Successfully fetched {len(trackers)} trackers from Exodus Privacy API")
            return trackers
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to fetch Exodus trackers - network error: {str(e)}"
            self.logger.error(error_msg)
            raise Exception(error_msg) from e
        except Exception as e:
            error_msg = f"Failed to fetch Exodus trackers - unexpected error: {str(e)}"
            self.logger.error(error_msg)
            raise Exception(error_msg) from e
    
    def clear_cache(self):
        """Clear the cached tracker data"""
        self._cache = None
        self.logger.debug("Exodus tracker cache cleared")
    
    def is_enabled(self) -> bool:
        """Check if Exodus API integration is enabled"""
        return self.enabled
    
    def get_cached_count(self) -> int:
        """Get the number of cached trackers"""
        return len(self._cache) if self._cache else 0