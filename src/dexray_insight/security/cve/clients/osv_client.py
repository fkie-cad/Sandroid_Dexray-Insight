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
OSV (Open Source Vulnerabilities) Client.

This module provides a client for the OSV vulnerability database API.
OSV is Google's vulnerability database for open source projects.

API Documentation: https://osv.dev/
"""

from datetime import datetime
from typing import Any
from typing import Optional

from ..models.vulnerability import AffectedLibrary
from ..models.vulnerability import CVESeverity
from ..models.vulnerability import CVEVulnerability
from ..models.vulnerability import VersionRange
from ..utils.rate_limiter import RateLimitConfig
from .base_client import BaseCVEClient


class OSVClient(BaseCVEClient):
    """Client for OSV (Open Source Vulnerabilities) database."""

    BASE_URL = "https://api.osv.dev"

    def _get_default_rate_limit_config(self) -> RateLimitConfig:
        """OSV rate limits - very conservative to avoid 429 errors during parallel scanning."""
        return RateLimitConfig(
            requests_per_minute=20,  # Further reduced from 30
            requests_per_hour=1200,  # Further reduced from 1800
            burst_limit=3,  # Further reduced from 5
            burst_window_seconds=60,  # Increased window
        )

    def _setup_headers(self):
        """Set up headers for OSV API."""
        self.session.headers.update(
            {
                "User-Agent": "dexray-insight-cve-scanner/1.0",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def get_source_name(self) -> str:
        """Get the name of this CVE source."""
        return "osv"

    def search_vulnerabilities(self, library_name: str, version: Optional[str] = None) -> list[CVEVulnerability]:
        """
        Search for vulnerabilities in OSV database.

        Args:
            library_name: Name of the library (should include ecosystem prefix)
            version: Specific version to check

        Returns:
            List of CVE vulnerabilities
        """
        vulnerabilities = []

        try:
            # OSV expects library names in specific formats (e.g., "Maven:com.example:library")
            query_variants = self._generate_query_variants(library_name)

            for query_name in query_variants:
                if version:
                    # Query for specific version
                    vulns = self._query_by_version(query_name, version)
                else:
                    # Query for all vulnerabilities affecting the package
                    vulns = self._query_by_package(query_name)

                vulnerabilities.extend(vulns)

            # Remove duplicates based on vulnerability ID
            seen_ids = set()
            unique_vulns = []
            for vuln in vulnerabilities:
                if vuln.cve_id not in seen_ids:
                    seen_ids.add(vuln.cve_id)
                    unique_vulns.append(vuln)

            self.logger.info(f"Found {len(unique_vulns)} vulnerabilities for {library_name} in OSV")
            return unique_vulns

        except Exception as e:
            self.logger.error(f"Error searching OSV for {library_name}: {e}")
            return []

    def _generate_query_variants(self, library_name: str) -> list[str]:
        """Generate different name variants to query OSV."""
        variants = [library_name]

        # If name doesn't contain ecosystem prefix, try common patterns
        if ":" not in library_name:
            # Try Maven format for Android libraries
            if library_name.count(".") >= 2:
                # Looks like a Java package name
                variants.append(f"Maven:{library_name}")
            else:
                # Try common Android prefixes
                common_prefixes = [
                    "com.google.android.gms",
                    "com.google.firebase",
                    "androidx",
                    "com.squareup.okhttp3",
                    "com.squareup.retrofit2",
                    "com.github.bumptech.glide",
                ]

                for prefix in common_prefixes:
                    if library_name.lower() in prefix or prefix.split(".")[-1] in library_name.lower():
                        variants.append(f"Maven:{prefix}:{library_name.lower()}")

        return list(set(variants))  # Remove duplicates

    def _query_by_version(self, package_name: str, version: str) -> list[CVEVulnerability]:
        """Query OSV for vulnerabilities affecting a specific version."""
        url = f"{self.BASE_URL}/v1/query"

        query_data = {"version": version, "package": {"name": package_name}}

        # Try to detect ecosystem from package name
        ecosystem = self._detect_ecosystem(package_name)
        if ecosystem:
            query_data["package"]["ecosystem"] = ecosystem

        try:
            response = self.session.post(url, json=query_data)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = []
            for vuln_data in data.get("vulns", []):
                vuln = self._parse_osv_vulnerability(vuln_data)
                if vuln:
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.debug(f"Error querying OSV by version for {package_name}:{version}: {e}")
            return []

    def _query_by_package(self, package_name: str) -> list[CVEVulnerability]:
        """Query OSV for all vulnerabilities affecting a package."""
        url = f"{self.BASE_URL}/v1/query"

        query_data = {"package": {"name": package_name}}

        ecosystem = self._detect_ecosystem(package_name)
        if ecosystem:
            query_data["package"]["ecosystem"] = ecosystem

        try:
            response = self.session.post(url, json=query_data)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = []
            for vuln_data in data.get("vulns", []):
                vuln = self._parse_osv_vulnerability(vuln_data)
                if vuln:
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.debug(f"Error querying OSV by package for {package_name}: {e}")
            return []

    def _detect_ecosystem(self, package_name: str) -> Optional[str]:
        """Detect ecosystem from package name."""
        if package_name.startswith("Maven:"):
            return "Maven"
        elif package_name.startswith("npm:"):
            return "npm"
        elif package_name.startswith("PyPI:"):
            return "PyPI"
        elif ":" in package_name:
            return package_name.split(":")[0]
        elif package_name.count(".") >= 2:
            # Looks like Java package
            return "Maven"
        else:
            return None

    def _parse_osv_vulnerability(self, osv_data: dict[str, Any]) -> Optional[CVEVulnerability]:
        """Parse OSV vulnerability data into CVEVulnerability object."""
        try:
            # Extract basic information
            vuln_id = osv_data.get("id", "")
            summary = osv_data.get("summary", "")
            details = osv_data.get("details", "")

            # Parse severity
            severity = CVESeverity.UNKNOWN
            cvss_score = None
            cvss_vector = None

            if "severity" in osv_data:
                severity_data = osv_data["severity"]
                if isinstance(severity_data, list) and severity_data:
                    severity_info = severity_data[0]
                    if "score" in severity_info:
                        cvss_score = float(severity_info["score"])
                        severity = CVEVulnerability.from_cvss_score(cvss_score)
                    cvss_vector = severity_info.get("type", "")

            # Parse dates
            published_date = None
            modified_date = None

            if "published" in osv_data:
                try:
                    published_date = datetime.fromisoformat(osv_data["published"].replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

            if "modified" in osv_data:
                try:
                    modified_date = datetime.fromisoformat(osv_data["modified"].replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

            # Parse affected libraries
            affected_libraries = []
            for affected in osv_data.get("affected", []):
                affected_lib = self._parse_affected_library(affected)
                if affected_lib:
                    affected_libraries.append(affected_lib)

            # Parse references
            references = []
            for ref in osv_data.get("references", []):
                if "url" in ref:
                    references.append(ref["url"])

            # Extract CVE ID if available
            cve_id = vuln_id
            for alias in osv_data.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            return CVEVulnerability(
                cve_id=cve_id,
                summary=summary,
                description=details,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published_date,
                modified_date=modified_date,
                affected_libraries=affected_libraries,
                references=references,
                source=self.get_source_name(),
                raw_data=osv_data,
            )

        except Exception as e:
            self.logger.warning(f"Error parsing OSV vulnerability data: {e}")
            return None

    def _parse_affected_library(self, affected_data: dict[str, Any]) -> Optional[AffectedLibrary]:
        """Parse affected library information from OSV data."""
        try:
            package_info = affected_data.get("package", {})
            library_name = package_info.get("name", "")
            ecosystem = package_info.get("ecosystem", "")
            purl = package_info.get("purl", "")

            # Parse version ranges
            version_ranges = []
            for range_info in affected_data.get("ranges", []):
                version_range = self._parse_version_range(range_info)
                if version_range:
                    version_ranges.append(version_range)

            # Parse specific versions
            for version in affected_data.get("versions", []):
                # Convert specific version to range
                version_range = VersionRange(introduced=version, last_affected=version)
                version_ranges.append(version_range)

            if library_name:
                return AffectedLibrary(name=library_name, ecosystem=ecosystem, purl=purl, version_ranges=version_ranges)

        except Exception as e:
            self.logger.warning(f"Error parsing affected library: {e}")

        return None

    def _parse_version_range(self, range_data: dict[str, Any]) -> Optional[VersionRange]:
        """Parse version range from OSV range data."""
        try:
            version_range = VersionRange()

            for event in range_data.get("events", []):
                if "introduced" in event:
                    version_range.introduced = event["introduced"]
                elif "fixed" in event:
                    version_range.fixed = event["fixed"]
                elif "last_affected" in event:
                    version_range.last_affected = event["last_affected"]
                elif "limit" in event:
                    version_range.limit = event["limit"]

            return version_range

        except Exception as e:
            self.logger.warning(f"Error parsing version range: {e}")
            return None

    def health_check(self) -> bool:
        """Check if OSV API is available."""
        try:
            self.logger.debug("OSV: Starting health check...")
            url = f"{self.BASE_URL}/v1/query"
            # Send a proper query with required ecosystem field
            payload = {"package": {"name": "test", "ecosystem": "PyPI"}}
            self.logger.debug(f"OSV: Making health check request to {url} with payload {payload}")
            response = self.session.post(url, json=payload, timeout=5)
            self.logger.debug(f"OSV: Health check response status: {response.status_code}")

            # 200 means found vulnerabilities, 404 means no vulnerabilities found - both are healthy
            if response.status_code in [200, 404]:
                self.logger.debug("OSV: Health check succeeded")
                return True
            else:
                self.logger.warning(
                    f"OSV: Health check failed with status {response.status_code}: {response.text[:200]}"
                )
                return False
        except Exception as e:
            self.logger.error(f"OSV: Health check failed with exception: {e}")
            import traceback

            self.logger.debug(f"OSV: Health check traceback: {traceback.format_exc()}")
            return False
