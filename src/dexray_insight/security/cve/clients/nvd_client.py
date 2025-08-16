#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NVD (National Vulnerability Database) Client

This module provides a client for the NVD vulnerability database API.
NVD is the U.S. government repository of standards-based vulnerability management data.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

from typing import List, Optional, Dict, Any
from datetime import datetime

from .base_client import BaseCVEClient
from ..models.vulnerability import CVEVulnerability, AffectedLibrary, VersionRange, CVESeverity
from ..utils.rate_limiter import RateLimitConfig


class NVDClient(BaseCVEClient):
    """Client for NVD (National Vulnerability Database)"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def _get_default_rate_limit_config(self) -> RateLimitConfig:
        """NVD has stricter rate limits - 5 requests per 30 seconds without API key"""
        if self.api_key:
            # With API key: 50 requests per 30 seconds
            return RateLimitConfig(
                requests_per_minute=100,
                requests_per_hour=6000,
                burst_limit=50,
                burst_window_seconds=30
            )
        else:
            # Without API key: 5 requests per 30 seconds
            return RateLimitConfig(
                requests_per_minute=10,
                requests_per_hour=600,
                burst_limit=5,
                burst_window_seconds=30
            )
    
    def _setup_headers(self):
        """Set up headers for NVD API"""
        headers = {
            'User-Agent': 'dexray-insight-cve-scanner/1.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        self.session.headers.update(headers)
    
    def get_source_name(self) -> str:
        """Get the name of this CVE source"""
        return "nvd"
    
    def search_vulnerabilities(self, library_name: str, version: Optional[str] = None) -> List[CVEVulnerability]:
        """
        Search for vulnerabilities in NVD database.
        
        Args:
            library_name: Name of the library
            version: Specific version to check (not directly supported by NVD API)
            
        Returns:
            List of CVE vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Generate search terms from library name
            search_terms = self._generate_search_terms(library_name)
            
            for search_term in search_terms:
                vulns = self._search_by_keyword(search_term)
                vulnerabilities.extend(vulns)
            
            # Remove duplicates based on CVE ID
            seen_ids = set()
            unique_vulns = []
            for vuln in vulnerabilities:
                if vuln.cve_id not in seen_ids:
                    seen_ids.add(vuln.cve_id)
                    unique_vulns.append(vuln)
            
            # Filter by version if provided
            if version:
                unique_vulns = self._filter_by_version(unique_vulns, version)
            
            self.logger.info(f"Found {len(unique_vulns)} vulnerabilities for {library_name} in NVD")
            return unique_vulns
            
        except Exception as e:
            self.logger.error(f"Error searching NVD for {library_name}: {e}")
            return []
    
    def _generate_search_terms(self, library_name: str) -> List[str]:
        """Generate search terms from library name"""
        terms = []
        
        # Add the library name as-is
        terms.append(library_name)
        
        # For Maven-style names, add variations
        if ":" in library_name:
            parts = library_name.split(":")
            if len(parts) >= 2:
                # Add artifact ID
                terms.append(parts[-1])
                # Add group ID
                if len(parts) >= 3:
                    terms.append(parts[-2])
        
        # For dotted names, add the last part
        elif "." in library_name:
            parts = library_name.split(".")
            if parts:
                terms.append(parts[-1])
        
        # Common Android library mappings
        android_mappings = {
            "firebase": "firebase",
            "gms": "google play services",
            "androidx": "androidx",
            "okhttp": "okhttp",
            "retrofit": "retrofit",
            "glide": "glide",
            "gson": "gson"
        }
        
        library_lower = library_name.lower()
        for key, value in android_mappings.items():
            if key in library_lower and value not in terms:
                terms.append(value)
        
        return list(set(terms))  # Remove duplicates
    
    def _search_by_keyword(self, keyword: str) -> List[CVEVulnerability]:
        """Search NVD by keyword"""
        vulnerabilities = []
        
        try:
            params = {
                'keywordSearch': keyword,
                'keywordExactMatch': False,
                'resultsPerPage': 100,  # Maximum allowed
                'startIndex': 0
            }
            
            # Make initial request
            response = self.session.get(self.BASE_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Parse vulnerabilities from first page
            for vuln_data in data.get('vulnerabilities', []):
                vuln = self._parse_nvd_vulnerability(vuln_data)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Handle pagination if there are more results
            total_results = data.get('totalResults', 0)
            if total_results > 100:
                # Limit to first 500 results to avoid excessive API calls
                max_results = min(total_results, 500)
                
                for start_index in range(100, max_results, 100):
                    params['startIndex'] = start_index
                    
                    response = self.session.get(self.BASE_URL, params=params)
                    response.raise_for_status()
                    page_data = response.json()
                    
                    for vuln_data in page_data.get('vulnerabilities', []):
                        vuln = self._parse_nvd_vulnerability(vuln_data)
                        if vuln:
                            vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.debug(f"Error searching NVD by keyword '{keyword}': {e}")
            return []
    
    def _parse_nvd_vulnerability(self, nvd_data: Dict[str, Any]) -> Optional[CVEVulnerability]:
        """Parse NVD vulnerability data into CVEVulnerability object"""
        try:
            cve_data = nvd_data.get('cve', {})
            
            # Extract basic information
            cve_id = cve_data.get('id', '')
            
            # Extract description (English preferred)
            description = ""
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Use description as summary if no separate summary
            summary = description[:200] + "..." if len(description) > 200 else description
            
            # Parse CVSS metrics
            severity = CVESeverity.UNKNOWN
            cvss_score = None
            cvss_vector = None
            
            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = float(cvss_data.get('baseScore', 0))
                cvss_vector = cvss_data.get('vectorString', '')
                severity = CVEVulnerability.from_cvss_score(cvss_score)
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = float(cvss_data.get('baseScore', 0))
                cvss_vector = cvss_data.get('vectorString', '')
                severity = CVEVulnerability.from_cvss_score(cvss_score)
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = float(cvss_data.get('baseScore', 0))
                cvss_vector = cvss_data.get('vectorString', '')
                severity = CVEVulnerability.from_cvss_score(cvss_score)
            
            # Parse dates
            published_date = None
            modified_date = None
            
            if 'published' in cve_data:
                try:
                    published_date = datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            if 'lastModified' in cve_data:
                try:
                    modified_date = datetime.fromisoformat(cve_data['lastModified'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            # Parse references
            references = []
            for ref in cve_data.get('references', []):
                if 'url' in ref:
                    references.append(ref['url'])
            
            # Parse affected configurations (CPE data)
            affected_libraries = self._parse_cpe_configurations(cve_data.get('configurations', []))
            
            return CVEVulnerability(
                cve_id=cve_id,
                summary=summary,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published_date,
                modified_date=modified_date,
                affected_libraries=affected_libraries,
                references=references,
                source=self.get_source_name(),
                raw_data=nvd_data
            )
            
        except Exception as e:
            self.logger.warning(f"Error parsing NVD vulnerability data: {e}")
            return None
    
    def _parse_cpe_configurations(self, configurations: List[Dict[str, Any]]) -> List[AffectedLibrary]:
        """Parse CPE configurations to extract affected libraries"""
        affected_libraries = []
        
        try:
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            cpe_name = cpe_match.get('criteria', '')
                            
                            # Parse CPE name (e.g., "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*")
                            library = self._parse_cpe_name(cpe_name)
                            if library:
                                # Add version range information if available
                                version_start = cpe_match.get('versionStartIncluding')
                                version_end = cpe_match.get('versionEndExcluding')
                                version_start_excluding = cpe_match.get('versionStartExcluding')
                                version_end_including = cpe_match.get('versionEndIncluding')
                                
                                if any([version_start, version_end, version_start_excluding, version_end_including]):
                                    version_range = VersionRange()
                                    if version_start:
                                        version_range.introduced = version_start
                                    elif version_start_excluding:
                                        version_range.introduced = version_start_excluding
                                    
                                    if version_end:
                                        version_range.fixed = version_end
                                    elif version_end_including:
                                        version_range.last_affected = version_end_including
                                    
                                    library.version_ranges = [version_range]
                                
                                affected_libraries.append(library)
        
        except Exception as e:
            self.logger.warning(f"Error parsing CPE configurations: {e}")
        
        return affected_libraries
    
    def _parse_cpe_name(self, cpe_name: str) -> Optional[AffectedLibrary]:
        """Parse CPE name to extract library information"""
        try:
            # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = cpe_name.split(':')
            if len(parts) >= 5:
                vendor = parts[3] if parts[3] != '*' else ''
                product = parts[4] if parts[4] != '*' else ''
                
                if product:
                    library_name = f"{vendor}:{product}" if vendor else product
                    return AffectedLibrary(
                        name=library_name,
                        ecosystem="",  # CPE doesn't specify ecosystem
                        purl="",
                        version_ranges=[]
                    )
        
        except Exception as e:
            self.logger.debug(f"Error parsing CPE name '{cpe_name}': {e}")
        
        return None
    
    def _filter_by_version(self, vulnerabilities: List[CVEVulnerability], version: str) -> List[CVEVulnerability]:
        """Filter vulnerabilities by version (basic string matching)"""
        filtered = []
        
        for vuln in vulnerabilities:
            # Check if version appears in description or affected libraries
            version_found = False
            
            # Check description
            if version in vuln.description.lower():
                version_found = True
            
            # Check affected libraries
            for lib in vuln.affected_libraries:
                for version_range in lib.version_ranges:
                    if (version_range.introduced and version >= version_range.introduced and
                        version_range.fixed and version < version_range.fixed):
                        version_found = True
                        break
                    elif (version_range.introduced and version >= version_range.introduced and
                          version_range.last_affected and version <= version_range.last_affected):
                        version_found = True
                        break
                if version_found:
                    break
            
            if version_found:
                filtered.append(vuln)
        
        return filtered
    
    def health_check(self) -> bool:
        """Check if NVD API is available"""
        try:
            # Test with a simple query
            params = {
                'keywordSearch': 'test',
                'resultsPerPage': 1
            }
            response = self.session.get(self.BASE_URL, params=params, timeout=5)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"NVD health check failed: {e}")
            return False