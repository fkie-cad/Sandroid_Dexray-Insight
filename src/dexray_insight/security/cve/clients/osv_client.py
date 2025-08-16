#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSV (Open Source Vulnerabilities) Client

This module provides a client for the OSV vulnerability database API.
OSV is Google's vulnerability database for open source projects.

API Documentation: https://osv.dev/
"""

from typing import List, Optional, Dict, Any
from datetime import datetime

from .base_client import BaseCVEClient
from ..models.vulnerability import CVEVulnerability, AffectedLibrary, VersionRange, CVESeverity
from ..utils.rate_limiter import RateLimitConfig


class OSVClient(BaseCVEClient):
    """Client for OSV (Open Source Vulnerabilities) database"""
    
    BASE_URL = "https://api.osv.dev"
    
    def _get_default_rate_limit_config(self) -> RateLimitConfig:
        """OSV has generous rate limits"""
        return RateLimitConfig(
            requests_per_minute=60,
            requests_per_hour=3600,
            burst_limit=10,
            burst_window_seconds=60
        )
    
    def _setup_headers(self):
        """Set up headers for OSV API"""
        self.session.headers.update({
            'User-Agent': 'dexray-insight-cve-scanner/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def get_source_name(self) -> str:
        """Get the name of this CVE source"""
        return "osv"
    
    def search_vulnerabilities(self, library_name: str, version: Optional[str] = None) -> List[CVEVulnerability]:
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
    
    def _generate_query_variants(self, library_name: str) -> List[str]:
        """Generate different name variants to query OSV"""
        variants = [library_name]
        
        # If name doesn't contain ecosystem prefix, try common patterns
        if ":" not in library_name:
            # Try Maven format for Android libraries
            if library_name.count('.') >= 2:
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
                    "com.github.bumptech.glide"
                ]
                
                for prefix in common_prefixes:
                    if library_name.lower() in prefix or prefix.split('.')[-1] in library_name.lower():
                        variants.append(f"Maven:{prefix}:{library_name.lower()}")
        
        return list(set(variants))  # Remove duplicates
    
    def _query_by_version(self, package_name: str, version: str) -> List[CVEVulnerability]:
        """Query OSV for vulnerabilities affecting a specific version"""
        url = f"{self.BASE_URL}/v1/query"
        
        query_data = {
            "version": version,
            "package": {
                "name": package_name
            }
        }
        
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
    
    def _query_by_package(self, package_name: str) -> List[CVEVulnerability]:
        """Query OSV for all vulnerabilities affecting a package"""
        url = f"{self.BASE_URL}/v1/query"
        
        query_data = {
            "package": {
                "name": package_name
            }
        }
        
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
        """Detect ecosystem from package name"""
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
    
    def _parse_osv_vulnerability(self, osv_data: Dict[str, Any]) -> Optional[CVEVulnerability]:
        """Parse OSV vulnerability data into CVEVulnerability object"""
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
                    published_date = datetime.fromisoformat(osv_data["published"].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            if "modified" in osv_data:
                try:
                    modified_date = datetime.fromisoformat(osv_data["modified"].replace('Z', '+00:00'))
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
                raw_data=osv_data
            )
            
        except Exception as e:
            self.logger.warning(f"Error parsing OSV vulnerability data: {e}")
            return None
    
    def _parse_affected_library(self, affected_data: Dict[str, Any]) -> Optional[AffectedLibrary]:
        """Parse affected library information from OSV data"""
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
                version_range = VersionRange(
                    introduced=version,
                    last_affected=version
                )
                version_ranges.append(version_range)
            
            if library_name:
                return AffectedLibrary(
                    name=library_name,
                    ecosystem=ecosystem,
                    purl=purl,
                    version_ranges=version_ranges
                )
            
        except Exception as e:
            self.logger.warning(f"Error parsing affected library: {e}")
        
        return None
    
    def _parse_version_range(self, range_data: Dict[str, Any]) -> Optional[VersionRange]:
        """Parse version range from OSV range data"""
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
        """Check if OSV API is available"""
        try:
            url = f"{self.BASE_URL}/v1/query"
            response = self.session.post(url, json={"package": {"name": "test"}}, timeout=5)
            return response.status_code in [200, 404]  # 404 is fine for test package
        except Exception as e:
            self.logger.error(f"OSV health check failed: {e}")
            return False