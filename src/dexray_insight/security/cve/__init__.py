#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""
CVE Vulnerability Scanning Framework for Dexray Insight.

This module provides comprehensive CVE (Common Vulnerabilities and Exposures) scanning
capabilities for detected libraries with known versions. It integrates with multiple
CVE databases and provides intelligent caching and rate limiting.

Features:
- Multiple CVE data sources (OSV, NVD, GitHub Advisory)
- Library name normalization and version parsing
- Intelligent caching and rate limiting
- Integration with security assessment framework
"""

from .clients.github_client import GitHubAdvisoryClient
from .clients.nvd_client import NVDClient
from .clients.osv_client import OSVClient
from .models.vulnerability import AffectedLibrary
from .models.vulnerability import CVESeverity
from .models.vulnerability import CVEVulnerability
from .models.vulnerability import VersionRange
from .utils.cache_manager import CVECacheManager
from .utils.rate_limiter import APIRateLimiter
from .utils.rate_limiter import RateLimitConfig

__all__ = [
    "CVEVulnerability",
    "AffectedLibrary",
    "VersionRange",
    "CVESeverity",
    "OSVClient",
    "NVDClient",
    "GitHubAdvisoryClient",
    "CVECacheManager",
    "APIRateLimiter",
    "RateLimitConfig",
]
