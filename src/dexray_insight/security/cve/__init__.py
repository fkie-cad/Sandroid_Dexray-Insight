#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE Vulnerability Scanning Framework for Dexray Insight

This module provides comprehensive CVE (Common Vulnerabilities and Exposures) scanning
capabilities for detected libraries with known versions. It integrates with multiple
CVE databases and provides intelligent caching and rate limiting.

Features:
- Multiple CVE data sources (OSV, NVD, GitHub Advisory)
- Library name normalization and version parsing
- Intelligent caching and rate limiting
- Integration with security assessment framework
"""

from .models.vulnerability import CVEVulnerability, AffectedLibrary, VersionRange, CVESeverity
from .clients.osv_client import OSVClient
from .clients.nvd_client import NVDClient
from .clients.github_client import GitHubAdvisoryClient
from .utils.cache_manager import CVECacheManager
from .utils.rate_limiter import APIRateLimiter, RateLimitConfig

__all__ = [
    'CVEVulnerability',
    'AffectedLibrary', 
    'VersionRange',
    'CVESeverity',
    'OSVClient',
    'NVDClient',
    'GitHubAdvisoryClient',
    'CVECacheManager',
    'APIRateLimiter',
    'RateLimitConfig'
]