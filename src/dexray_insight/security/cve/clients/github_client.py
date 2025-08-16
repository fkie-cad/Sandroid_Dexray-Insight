#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Advisory Database Client

This module provides a client for the GitHub Advisory Database API.
GitHub Advisory Database contains security advisories for open source projects.

API Documentation: https://docs.github.com/en/rest/security-advisories
"""

from typing import List, Optional, Dict, Any
from datetime import datetime

from .base_client import BaseCVEClient
from ..models.vulnerability import CVEVulnerability, AffectedLibrary, VersionRange, CVESeverity
from ..utils.rate_limiter import RateLimitConfig


class GitHubAdvisoryClient(BaseCVEClient):
    """Client for GitHub Advisory Database"""
    
    BASE_URL = "https://api.github.com/advisories"
    
    def _get_default_rate_limit_config(self) -> RateLimitConfig:
        """GitHub has rate limits - 60/hour without auth, 5000/hour with token"""
        if self.api_key:
            # With token: 5000 requests per hour
            return RateLimitConfig(
                requests_per_minute=80,
                requests_per_hour=5000,
                burst_limit=20,
                burst_window_seconds=60
            )
        else:
            # Without token: 60 requests per hour
            return RateLimitConfig(
                requests_per_minute=1,
                requests_per_hour=60,
                burst_limit=5,
                burst_window_seconds=300
            )
    
    def _setup_headers(self):
        """Set up headers for GitHub API"""
        headers = {
            'User-Agent': 'dexray-insight-cve-scanner/1.0',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        self.session.headers.update(headers)
    
    def get_source_name(self) -> str:
        """Get the name of this CVE source"""
        return "github"
    
    def search_vulnerabilities(self, library_name: str, version: Optional[str] = None) -> List[CVEVulnerability]:
        """
        Search for vulnerabilities in GitHub Advisory Database.
        
        Args:
            library_name: Name of the library
            version: Specific version to check
            
        Returns:
            List of CVE vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Detect ecosystem from library name
            ecosystem = self._detect_ecosystem(library_name)
            
            # Generate search variants
            search_variants = self._generate_search_variants(library_name)
            
            for search_name in search_variants:
                vulns = self._search_by_package(search_name, ecosystem)
                vulnerabilities.extend(vulns)
            
            # Remove duplicates based on GHSA ID
            seen_ids = set()
            unique_vulns = []
            for vuln in vulnerabilities:
                vuln_id = vuln.raw_data.get('ghsa_id', vuln.cve_id)
                if vuln_id not in seen_ids:
                    seen_ids.add(vuln_id)
                    unique_vulns.append(vuln)
            
            # Filter by version if provided
            if version:
                unique_vulns = self._filter_by_version(unique_vulns, version)
            
            self.logger.info(f"Found {len(unique_vulns)} vulnerabilities for {library_name} in GitHub")
            return unique_vulns
            
        except Exception as e:
            self.logger.error(f"Error searching GitHub Advisory for {library_name}: {e}")
            return []
    
    def _detect_ecosystem(self, library_name: str) -> Optional[str]:
        """Detect ecosystem from library name"""
        # GitHub uses specific ecosystem names
        if ":" in library_name:
            prefix = library_name.split(":")[0].lower()
            ecosystem_map = {
                "maven": "maven",
                "npm": "npm", 
                "pypi": "pip",
                "nuget": "nuget"
            }
            return ecosystem_map.get(prefix)
        
        # Try to infer from structure
        if library_name.count(".") >= 2:
            # Looks like Java package
            return "maven"
        elif "-" in library_name and "." not in library_name:
            # Might be npm package
            return "npm"
        
        return None
    
    def _generate_search_variants(self, library_name: str) -> List[str]:
        """Generate search variants for library name"""
        variants = []
        
        # Original name
        variants.append(library_name)
        
        # Remove ecosystem prefix if present
        if ":" in library_name:
            parts = library_name.split(":")
            if len(parts) >= 2:
                # Add artifact name
                variants.append(parts[-1])
                # Add group:artifact for Maven
                if len(parts) >= 3:
                    variants.append(f"{parts[-2]}:{parts[-1]}")
        
        # For dotted names, try just the last part
        if "." in library_name:
            parts = library_name.split(".")
            if parts:
                variants.append(parts[-1])
        
        # Common Android library name mappings
        android_mappings = {
            "firebase-messaging": "firebase-messaging",
            "play-services": "play-services-base",
            "androidx.core": "core",
            "androidx.appcompat": "appcompat",
            "okhttp3": "okhttp",
            "retrofit2": "retrofit"
        }
        
        for pattern, mapped_name in android_mappings.items():
            if pattern in library_name.lower():
                variants.append(mapped_name)
        
        return list(set(variants))  # Remove duplicates
    
    def _search_by_package(self, package_name: str, ecosystem: Optional[str] = None) -> List[CVEVulnerability]:
        """Search GitHub Advisory Database by package name"""
        vulnerabilities = []
        
        try:
            params = {
                'per_page': 100,  # Maximum allowed
                'page': 1
            }
            
            # Add ecosystem filter if detected
            if ecosystem:
                params['ecosystem'] = ecosystem
            
            # GitHub API supports searching by affects parameter
            params['affects'] = package_name
            
            # Make initial request
            response = self.session.get(self.BASE_URL, params=params)
            response.raise_for_status()
            advisories = response.json()
            
            # Parse advisories from first page
            for advisory in advisories:
                vuln = self._parse_github_advisory(advisory)
                if vuln and self._is_relevant_advisory(advisory, package_name):
                    vulnerabilities.append(vuln)
            
            # Handle pagination (limited to first 300 results)
            max_pages = 3
            current_page = 1
            
            while current_page < max_pages and len(advisories) == 100:
                current_page += 1
                params['page'] = current_page
                
                response = self.session.get(self.BASE_URL, params=params)
                response.raise_for_status()
                advisories = response.json()
                
                for advisory in advisories:
                    vuln = self._parse_github_advisory(advisory)
                    if vuln and self._is_relevant_advisory(advisory, package_name):
                        vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.debug(f"Error searching GitHub Advisory for '{package_name}': {e}")
            return []
    
    def _is_relevant_advisory(self, advisory: Dict[str, Any], package_name: str) -> bool:
        """Check if advisory is relevant to the package"""
        package_lower = package_name.lower()
        
        # Check if package name appears in summary or description
        summary = advisory.get('summary', '').lower()
        description = advisory.get('description', '').lower()
        
        if package_lower in summary or package_lower in description:
            return True
        
        # Check vulnerabilities array for affected packages
        for vuln in advisory.get('vulnerabilities', []):
            package_info = vuln.get('package', {})
            if package_info.get('name', '').lower() == package_lower:
                return True
        
        return False
    
    def _parse_github_advisory(self, advisory: Dict[str, Any]) -> Optional[CVEVulnerability]:
        """Parse GitHub advisory data into CVEVulnerability object"""
        try:
            # Extract basic information
            ghsa_id = advisory.get('ghsa_id', '')
            cve_id = advisory.get('cve_id', ghsa_id)  # Use GHSA ID if no CVE
            summary = advisory.get('summary', '')
            description = advisory.get('description', '')
            
            # Parse severity
            severity_str = advisory.get('severity', '').upper()
            severity = CVESeverity.UNKNOWN
            cvss_score = None
            
            # Map GitHub severity to our enum
            severity_map = {
                'LOW': CVESeverity.LOW,
                'MODERATE': CVESeverity.MEDIUM,
                'HIGH': CVESeverity.HIGH,
                'CRITICAL': CVESeverity.CRITICAL
            }
            severity = severity_map.get(severity_str, CVESeverity.UNKNOWN)
            
            # Extract CVSS score if available
            cvss = advisory.get('cvss', {})
            if 'score' in cvss:
                cvss_score = float(cvss['score'])
            
            # Parse dates
            published_date = None
            modified_date = None
            
            if 'published_at' in advisory:
                try:
                    published_date = datetime.fromisoformat(advisory['published_at'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            if 'updated_at' in advisory:
                try:
                    modified_date = datetime.fromisoformat(advisory['updated_at'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            # Parse affected libraries
            affected_libraries = []
            for vuln in advisory.get('vulnerabilities', []):
                affected_lib = self._parse_affected_package(vuln)
                if affected_lib:
                    affected_libraries.append(affected_lib)
            
            # Parse references
            references = []
            for ref in advisory.get('references', []):
                if 'url' in ref:
                    references.append(ref['url'])
            
            # Add permalink as reference
            if 'html_url' in advisory:
                references.append(advisory['html_url'])
            
            return CVEVulnerability(
                cve_id=cve_id,
                summary=summary,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss.get('vector_string'),
                published_date=published_date,
                modified_date=modified_date,
                affected_libraries=affected_libraries,
                references=references,
                source=self.get_source_name(),
                raw_data=advisory
            )
            
        except Exception as e:
            self.logger.warning(f"Error parsing GitHub advisory data: {e}")
            return None
    
    def _parse_affected_package(self, vuln_data: Dict[str, Any]) -> Optional[AffectedLibrary]:
        """Parse affected package information from GitHub advisory"""
        try:
            package_info = vuln_data.get('package', {})
            library_name = package_info.get('name', '')
            ecosystem = package_info.get('ecosystem', '')
            
            # Parse version ranges
            version_ranges = []
            for range_info in vuln_data.get('vulnerable_version_range', '').split(','):
                range_info = range_info.strip()
                if range_info:
                    version_range = self._parse_version_range_string(range_info)
                    if version_range:
                        version_ranges.append(version_range)
            
            # Also check patched_versions and vulnerable_functions
            patched_versions = vuln_data.get('patched_versions', '')
            if patched_versions:
                # This indicates versions that are NOT vulnerable
                # We'll store this information but it's complex to parse
                pass
            
            if library_name:
                return AffectedLibrary(
                    name=library_name,
                    ecosystem=ecosystem,
                    purl="",  # GitHub doesn't provide PURL
                    version_ranges=version_ranges
                )
            
        except Exception as e:
            self.logger.warning(f"Error parsing affected package: {e}")
        
        return None
    
    def _parse_version_range_string(self, range_str: str) -> Optional[VersionRange]:
        """Parse version range string like '< 1.0.0', '>= 1.2.0, < 2.0.0'"""
        try:
            version_range = VersionRange()
            
            # Simple parsing for common patterns
            range_str = range_str.strip()
            
            if range_str.startswith('< '):
                version_range.fixed = range_str[2:].strip()
            elif range_str.startswith('<= '):
                version_range.last_affected = range_str[3:].strip()
            elif range_str.startswith('>= '):
                version_range.introduced = range_str[3:].strip()
            elif range_str.startswith('> '):
                # Handle > by adding a small increment (simplified)
                version_range.introduced = range_str[2:].strip()
            elif range_str.startswith('= '):
                # Exact version affected
                version = range_str[2:].strip()
                version_range.introduced = version
                version_range.last_affected = version
            
            return version_range
            
        except Exception as e:
            self.logger.warning(f"Error parsing version range '{range_str}': {e}")
            return None
    
    def _filter_by_version(self, vulnerabilities: List[CVEVulnerability], version: str) -> List[CVEVulnerability]:
        """Filter vulnerabilities by version"""
        filtered = []
        
        for vuln in vulnerabilities:
            version_matches = False
            
            # Check affected libraries
            for lib in vuln.affected_libraries:
                for version_range in lib.version_ranges:
                    if self._version_in_range(version, version_range):
                        version_matches = True
                        break
                if version_matches:
                    break
            
            # If no specific version ranges, include the vulnerability
            if not vuln.affected_libraries or not any(lib.version_ranges for lib in vuln.affected_libraries):
                version_matches = True
            
            if version_matches:
                filtered.append(vuln)
        
        return filtered
    
    def _version_in_range(self, version: str, version_range: VersionRange) -> bool:
        """Check if version falls within the vulnerability range (simplified)"""
        try:
            # Simplified version comparison - in practice you'd use semantic versioning
            if version_range.introduced and version < version_range.introduced:
                return False
            
            if version_range.fixed and version >= version_range.fixed:
                return False
            
            if version_range.last_affected and version > version_range.last_affected:
                return False
            
            return True
            
        except Exception:
            # If version comparison fails, assume it might be affected
            return True
    
    def health_check(self) -> bool:
        """Check if GitHub API is available"""
        try:
            # Test with a simple request
            params = {'per_page': 1}
            response = self.session.get(self.BASE_URL, params=params, timeout=5)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"GitHub Advisory health check failed: {e}")
            return False