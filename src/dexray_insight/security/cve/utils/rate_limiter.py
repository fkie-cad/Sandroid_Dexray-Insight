#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Rate Limiter for CVE Scanning

This module provides rate limiting functionality to respect API limits
of various CVE data sources.
"""

import time
from typing import Dict, Optional
from dataclasses import dataclass
from threading import Lock
import logging


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_minute: int = 30
    requests_per_hour: Optional[int] = None
    requests_per_day: Optional[int] = None
    burst_limit: Optional[int] = None  # Maximum requests in burst
    burst_window_seconds: int = 60     # Time window for burst detection


class APIRateLimiter:
    """Rate limiter for API requests to CVE databases"""
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or RateLimitConfig()
        
        # Track request timestamps for different time windows
        self.request_history: Dict[str, list] = {
            "minute": [],
            "hour": [],
            "day": [],
            "burst": []
        }
        
        # Lock for thread safety
        self._lock = Lock()
        
        # Last request time for minimum delay enforcement
        self.last_request_time: Optional[float] = None
        
        # Calculate minimum delay between requests
        self.min_delay = 60.0 / self.config.requests_per_minute if self.config.requests_per_minute > 0 else 0
    
    def can_make_request(self) -> bool:
        """
        Check if a request can be made without violating rate limits.
        
        Returns:
            True if request can be made, False otherwise
        """
        with self._lock:
            current_time = time.time()
            
            # Clean old entries
            self._clean_request_history(current_time)
            
            # Check each rate limit
            if not self._check_minute_limit(current_time):
                return False
            
            if self.config.requests_per_hour and not self._check_hour_limit(current_time):
                return False
            
            if self.config.requests_per_day and not self._check_day_limit(current_time):
                return False
            
            if self.config.burst_limit and not self._check_burst_limit(current_time):
                return False
            
            return True
    
    def wait_for_request(self) -> float:
        """
        Wait until a request can be made, respecting rate limits.
        
        Returns:
            Time waited in seconds
        """
        start_time = time.time()
        
        while not self.can_make_request():
            wait_time = self._calculate_wait_time()
            if wait_time > 0:
                self.logger.debug(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                time.sleep(min(wait_time, 1.0))  # Sleep in small increments
        
        return time.time() - start_time
    
    def record_request(self):
        """Record that a request was made"""
        with self._lock:
            current_time = time.time()
            
            # Add to all tracking lists
            for window in self.request_history:
                self.request_history[window].append(current_time)
            
            self.last_request_time = current_time
            
            # Clean old entries
            self._clean_request_history(current_time)
    
    def _clean_request_history(self, current_time: float):
        """Remove old entries from request history"""
        # Clean minute history (keep last 60 seconds)
        self.request_history["minute"] = [
            t for t in self.request_history["minute"] 
            if current_time - t < 60
        ]
        
        # Clean hour history (keep last 3600 seconds)
        self.request_history["hour"] = [
            t for t in self.request_history["hour"] 
            if current_time - t < 3600
        ]
        
        # Clean day history (keep last 86400 seconds)
        self.request_history["day"] = [
            t for t in self.request_history["day"] 
            if current_time - t < 86400
        ]
        
        # Clean burst history (keep last burst_window_seconds)
        self.request_history["burst"] = [
            t for t in self.request_history["burst"] 
            if current_time - t < self.config.burst_window_seconds
        ]
    
    def _check_minute_limit(self, current_time: float) -> bool:
        """Check if minute rate limit allows request"""
        if self.config.requests_per_minute <= 0:
            return True
        
        recent_requests = len(self.request_history["minute"])
        return recent_requests < self.config.requests_per_minute
    
    def _check_hour_limit(self, current_time: float) -> bool:
        """Check if hour rate limit allows request"""
        if not self.config.requests_per_hour or self.config.requests_per_hour <= 0:
            return True
        
        recent_requests = len(self.request_history["hour"])
        return recent_requests < self.config.requests_per_hour
    
    def _check_day_limit(self, current_time: float) -> bool:
        """Check if day rate limit allows request"""
        if not self.config.requests_per_day or self.config.requests_per_day <= 0:
            return True
        
        recent_requests = len(self.request_history["day"])
        return recent_requests < self.config.requests_per_day
    
    def _check_burst_limit(self, current_time: float) -> bool:
        """Check if burst limit allows request"""
        if not self.config.burst_limit or self.config.burst_limit <= 0:
            return True
        
        recent_requests = len(self.request_history["burst"])
        return recent_requests < self.config.burst_limit
    
    def _calculate_wait_time(self) -> float:
        """Calculate how long to wait before next request"""
        current_time = time.time()
        wait_times = []
        
        # Check minimum delay since last request
        if self.last_request_time and self.min_delay > 0:
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.min_delay:
                wait_times.append(self.min_delay - time_since_last)
        
        # Check minute limit
        if self.config.requests_per_minute > 0:
            minute_requests = len(self.request_history["minute"])
            if minute_requests >= self.config.requests_per_minute:
                oldest_request = min(self.request_history["minute"])
                wait_times.append(60 - (current_time - oldest_request))
        
        # Check hour limit
        if self.config.requests_per_hour and self.config.requests_per_hour > 0:
            hour_requests = len(self.request_history["hour"])
            if hour_requests >= self.config.requests_per_hour:
                oldest_request = min(self.request_history["hour"])
                wait_times.append(3600 - (current_time - oldest_request))
        
        # Check day limit
        if self.config.requests_per_day and self.config.requests_per_day > 0:
            day_requests = len(self.request_history["day"])
            if day_requests >= self.config.requests_per_day:
                oldest_request = min(self.request_history["day"])
                wait_times.append(86400 - (current_time - oldest_request))
        
        # Check burst limit
        if self.config.burst_limit and self.config.burst_limit > 0:
            burst_requests = len(self.request_history["burst"])
            if burst_requests >= self.config.burst_limit:
                oldest_request = min(self.request_history["burst"])
                wait_times.append(self.config.burst_window_seconds - (current_time - oldest_request))
        
        return max(wait_times) if wait_times else 0
    
    def get_rate_limit_status(self) -> Dict[str, any]:
        """Get current rate limit status"""
        current_time = time.time()
        
        with self._lock:
            self._clean_request_history(current_time)
            
            return {
                "requests_last_minute": len(self.request_history["minute"]),
                "requests_last_hour": len(self.request_history["hour"]),
                "requests_last_day": len(self.request_history["day"]),
                "requests_in_burst_window": len(self.request_history["burst"]),
                "can_make_request": self.can_make_request(),
                "wait_time_seconds": self._calculate_wait_time(),
                "config": {
                    "requests_per_minute": self.config.requests_per_minute,
                    "requests_per_hour": self.config.requests_per_hour,
                    "requests_per_day": self.config.requests_per_day,
                    "burst_limit": self.config.burst_limit,
                    "burst_window_seconds": self.config.burst_window_seconds
                }
            }
    
    def reset(self):
        """Reset rate limiter state"""
        with self._lock:
            for window in self.request_history:
                self.request_history[window] = []
            self.last_request_time = None
            
        self.logger.info("Rate limiter state reset")