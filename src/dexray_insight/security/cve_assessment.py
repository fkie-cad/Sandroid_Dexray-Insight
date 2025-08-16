#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE (Common Vulnerabilities and Exposures) Assessment

This module provides comprehensive CVE vulnerability scanning for detected libraries
by querying multiple online CVE databases including OSV, NVD, and GitHub Advisory.
"""

import logging
from typing import List, Dict, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment
from .cve.clients.osv_client import OSVClient
from .cve.clients.nvd_client import NVDClient
from .cve.clients.github_client import GitHubAdvisoryClient
from .cve.utils.cache_manager import CVECacheManager
from .cve.models.vulnerability import CVEVulnerability, CVESeverity


@register_assessment('cve_scanning')
class CVEAssessment(BaseSecurityAssessment):
    """
    CVE vulnerability scanning assessment using online databases.
    
    This assessment scans detected libraries with identified versions against
    multiple CVE databases to identify known security vulnerabilities.
    
    Supported CVE sources:
    - OSV (Open Source Vulnerabilities) - Google's vulnerability database
    - NVD (National Vulnerability Database) - NIST's vulnerability database  
    - GitHub Advisory Database - GitHub's security advisory database
    
    Features:
    - Rate limiting to respect API limits
    - Caching to avoid repeated queries
    - Parallel scanning for performance
    - Severity-based finding classification
    - Comprehensive remediation guidance
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "CVE Vulnerability Scanning"
        
        # Get security configuration
        security_config = config.get('security', {})
        
        # CVE scanning configuration
        cve_config = security_config.get('cve_scanning', {})
        
        # Check if CVE scanning is enabled
        if not cve_config.get('enabled', False):
            self.logger.info("CVE scanning is disabled in configuration")
            self.sources_config = {}
            self.scan_config = {}
            self.cache_manager = None
            self.clients = {}
            return
        
        # CVE data sources configuration
        sources_config = cve_config.get('sources', {})
        self.sources_config = {
            'osv': {
                'enabled': sources_config.get('osv', {}).get('enabled', True),
                'api_key': sources_config.get('osv', {}).get('api_key')
            },
            'nvd': {
                'enabled': sources_config.get('nvd', {}).get('enabled', True),
                'api_key': sources_config.get('nvd', {}).get('api_key')
            },
            'github': {
                'enabled': sources_config.get('github', {}).get('enabled', True),
                'api_key': sources_config.get('github', {}).get('api_key')
            }
        }
        
        # Scanning configuration
        self.scan_config = {
            'max_workers': cve_config.get('max_workers', 3),
            'timeout_seconds': cve_config.get('timeout_seconds', 30),
            'min_confidence': cve_config.get('min_confidence', 0.7),
            'cache_duration_hours': cve_config.get('cache_duration_hours', 24),
            'max_libraries_per_source': cve_config.get('max_libraries_per_source', 50)
        }
        
        # Initialize cache manager
        cache_dir_config = cve_config.get('cache_dir')
        if cache_dir_config:
            cache_dir = Path(cache_dir_config)
        else:
            cache_dir = Path.home() / '.dexray_insight' / 'cve_cache'
            
        self.cache_manager = CVECacheManager(
            cache_dir=cache_dir,
            cache_duration_hours=self.scan_config['cache_duration_hours']
        )
        
        # Initialize CVE clients
        self.clients = {}
        self._initialize_clients()
        
        # Threading lock for thread-safe operations
        self._lock = threading.Lock()
        
        # Vulnerability aggregation
        self.found_vulnerabilities = []
        
    def _initialize_clients(self):
        """Initialize CVE database clients based on configuration"""
        
        if self.sources_config.get('osv', {}).get('enabled', True):
            try:
                self.clients['osv'] = OSVClient(
                    api_key=self.sources_config.get('osv', {}).get('api_key'),
                    timeout=self.scan_config['timeout_seconds'],
                    cache_manager=self.cache_manager
                )
                self.logger.info("OSV client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize OSV client: {e}")
        
        if self.sources_config.get('nvd', {}).get('enabled', True):
            try:
                self.clients['nvd'] = NVDClient(
                    api_key=self.sources_config.get('nvd', {}).get('api_key'),
                    timeout=self.scan_config['timeout_seconds'],
                    cache_manager=self.cache_manager
                )
                self.logger.info("NVD client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize NVD client: {e}")
        
        if self.sources_config.get('github', {}).get('enabled', True):
            try:
                self.clients['github'] = GitHubAdvisoryClient(
                    api_key=self.sources_config.get('github', {}).get('api_key'),
                    timeout=self.scan_config['timeout_seconds'],
                    cache_manager=self.cache_manager
                )
                self.logger.info("GitHub Advisory client initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize GitHub Advisory client: {e}")
        
        if not self.clients:
            self.logger.warning("No CVE clients were successfully initialized")
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Perform CVE vulnerability assessment on detected libraries.
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to CVE vulnerabilities
        """
        findings = []
        
        try:
            # Check if CVE scanning is enabled
            if not hasattr(self, 'clients') or not self.clients:
                self.logger.debug("CVE scanning is disabled or no clients available")
                return findings
            
            # Extract libraries with versions for scanning
            scannable_libraries = self._extract_scannable_libraries(analysis_results)
            
            if not scannable_libraries:
                self.logger.info("No libraries with versions found for CVE scanning")
                return findings
            
            self.logger.info(f"Starting CVE scan for {len(scannable_libraries)} libraries")
            
            # Perform CVE scanning
            vulnerabilities = self._scan_libraries_for_cves(scannable_libraries)
            
            if vulnerabilities:
                self.logger.info(f"Found {len(vulnerabilities)} CVE vulnerabilities")
                
                # Create security findings from vulnerabilities
                findings = self._create_security_findings(vulnerabilities, scannable_libraries)
            else:
                self.logger.info("No CVE vulnerabilities found")
                
                # Create informational finding about successful scan
                findings.append(SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.INFO,
                    title="CVE Vulnerability Scan Completed",
                    description=f"Successfully scanned {len(scannable_libraries)} libraries against CVE databases. No known vulnerabilities found.",
                    evidence=[f"Scanned library: {lib['name']} {lib['version']}" for lib in scannable_libraries[:10]],
                    recommendations=[
                        "Continue monitoring libraries for new vulnerabilities",
                        "Keep libraries updated to latest versions",
                        "Consider automated dependency scanning in CI/CD",
                        "Subscribe to security advisories for critical libraries"
                    ]
                ))
            
        except Exception as e:
            self.logger.error(f"CVE assessment failed: {str(e)}")
            
            # Create error finding
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.LOW,
                title="CVE Scanning Error",
                description=f"CVE vulnerability scanning encountered an error: {str(e)}",
                evidence=[f"Error details: {str(e)}"],
                recommendations=[
                    "Check CVE scanning configuration",
                    "Verify API keys and network connectivity",
                    "Review CVE scanning logs for details",
                    "Consider manual vulnerability assessment"
                ]
            ))
        
        return findings
    
    def _extract_scannable_libraries(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract libraries with versions that can be scanned for CVEs"""
        scannable_libraries = []
        
        # Get library detection results
        library_results = analysis_results.get('library_detection', {})
        if hasattr(library_results, 'to_dict'):
            library_data = library_results.to_dict()
        else:
            library_data = library_results
        
        detected_libraries = library_data.get('detected_libraries', [])
        
        for library in detected_libraries:
            if isinstance(library, dict):
                library_name = library.get('name', '')
                library_version = library.get('version', '')
                confidence = library.get('confidence', 0)
                
                # Only scan libraries with versions and high confidence
                if (library_name and library_version and 
                    confidence >= self.scan_config['min_confidence']):
                    
                    scannable_libraries.append({
                        'name': library_name,
                        'version': library_version,
                        'confidence': confidence,
                        'category': library.get('category', 'unknown'),
                        'detection_method': library.get('detection_method', 'unknown')
                    })
        
        # Limit number of libraries to scan per source to avoid excessive API usage
        max_libs = self.scan_config['max_libraries_per_source']
        if len(scannable_libraries) > max_libs:
            # Prioritize by confidence
            scannable_libraries.sort(key=lambda x: x['confidence'], reverse=True)
            scannable_libraries = scannable_libraries[:max_libs]
            self.logger.info(f"Limited CVE scanning to top {max_libs} libraries by confidence")
        
        return scannable_libraries
    
    def _scan_libraries_for_cves(self, libraries: List[Dict[str, Any]]) -> List[CVEVulnerability]:
        """Scan libraries for CVE vulnerabilities using multiple sources"""
        all_vulnerabilities = []
        
        # Perform health checks on clients
        healthy_clients = {}
        for source, client in self.clients.items():
            if client.health_check():
                healthy_clients[source] = client
                self.logger.debug(f"{source} client is healthy")
            else:
                self.logger.warning(f"{source} client failed health check")
        
        if not healthy_clients:
            self.logger.error("No healthy CVE clients available")
            return all_vulnerabilities
        
        # Scan libraries in parallel
        with ThreadPoolExecutor(max_workers=self.scan_config['max_workers']) as executor:
            future_to_library = {}
            
            for library in libraries:
                for source, client in healthy_clients.items():
                    future = executor.submit(
                        self._scan_single_library,
                        client, source, library['name'], library['version']
                    )
                    future_to_library[future] = (source, library)
            
            # Collect results
            for future in as_completed(future_to_library, timeout=self.scan_config['timeout_seconds'] + 30):
                source, library = future_to_library[future]
                
                try:
                    vulnerabilities = future.result()
                    if vulnerabilities:
                        self.logger.debug(f"Found {len(vulnerabilities)} vulnerabilities for {library['name']} from {source}")
                        all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    self.logger.warning(f"CVE scan failed for {library['name']} via {source}: {e}")
        
        # Remove duplicates based on CVE ID
        unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
        
        return unique_vulnerabilities
    
    def _scan_single_library(self, client, source: str, library_name: str, version: str) -> List[CVEVulnerability]:
        """Scan a single library using a specific CVE client"""
        try:
            vulnerabilities = client.search_vulnerabilities_with_cache(library_name, version)
            
            # Add source metadata to vulnerabilities
            for vuln in vulnerabilities:
                vuln.source = source
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.debug(f"Error scanning {library_name}:{version} via {source}: {e}")
            return []
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[CVEVulnerability]) -> List[CVEVulnerability]:
        """Remove duplicate vulnerabilities based on CVE ID"""
        seen_cves = {}
        unique_vulns = []
        
        for vuln in vulnerabilities:
            cve_id = vuln.cve_id
            
            if cve_id not in seen_cves:
                seen_cves[cve_id] = vuln
                unique_vulns.append(vuln)
            else:
                # Keep the vulnerability with higher severity or more recent data
                existing = seen_cves[cve_id]
                if (vuln.severity.value > existing.severity.value or
                    (vuln.modified_date and existing.modified_date and 
                     vuln.modified_date > existing.modified_date)):
                    seen_cves[cve_id] = vuln
                    # Replace in unique list
                    for i, existing_vuln in enumerate(unique_vulns):
                        if existing_vuln.cve_id == cve_id:
                            unique_vulns[i] = vuln
                            break
        
        return unique_vulns
    
    def _create_security_findings(self, vulnerabilities: List[CVEVulnerability], 
                                 libraries: List[Dict[str, Any]]) -> List[SecurityFinding]:
        """Create security findings from CVE vulnerabilities"""
        findings = []
        
        # Group vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.CRITICAL]
        high_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.HIGH]
        medium_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.MEDIUM]
        low_vulns = [v for v in vulnerabilities if v.severity == CVESeverity.LOW]
        
        # Create findings for each severity level
        if critical_vulns:
            findings.append(self._create_severity_finding(
                critical_vulns, AnalysisSeverity.CRITICAL,
                "Critical CVE Vulnerabilities Detected",
                "Application uses libraries with critical CVE vulnerabilities that allow remote code execution or complete system compromise."
            ))
        
        if high_vulns:
            findings.append(self._create_severity_finding(
                high_vulns, AnalysisSeverity.HIGH,
                "High-Risk CVE Vulnerabilities Found",
                "Application contains libraries with high-risk CVE vulnerabilities that could lead to significant security breaches."
            ))
        
        if medium_vulns:
            findings.append(self._create_severity_finding(
                medium_vulns, AnalysisSeverity.MEDIUM,
                "Medium-Risk CVE Vulnerabilities Identified",
                "Application uses libraries with medium-risk CVE vulnerabilities that should be addressed."
            ))
        
        if low_vulns:
            findings.append(self._create_severity_finding(
                low_vulns, AnalysisSeverity.LOW,
                "Low-Risk CVE Vulnerabilities Present",
                "Application contains libraries with low-risk CVE vulnerabilities for awareness."
            ))
        
        # Add summary finding
        if vulnerabilities:
            total_vulns = len(vulnerabilities)
            scanned_libs = len(libraries)
            
            summary_evidence = [
                f"Total CVE vulnerabilities found: {total_vulns}",
                f"Libraries scanned: {scanned_libs}",
                f"Critical: {len(critical_vulns)}, High: {len(high_vulns)}, Medium: {len(medium_vulns)}, Low: {len(low_vulns)}",
                f"CVE sources used: {', '.join(self.clients.keys())}"
            ]
            
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.INFO,
                title="CVE Vulnerability Scan Summary",
                description=f"Comprehensive CVE scan completed. Found {total_vulns} vulnerabilities across {scanned_libs} libraries.",
                evidence=summary_evidence,
                recommendations=[
                    "Prioritize fixing critical and high-severity vulnerabilities",
                    "Update vulnerable libraries to patched versions",
                    "Implement automated CVE monitoring for dependencies",
                    "Consider alternative libraries for components with multiple CVEs",
                    "Review application's exposure to identified vulnerabilities"
                ]
            ))
        
        return findings
    
    def _create_severity_finding(self, vulnerabilities: List[CVEVulnerability], 
                                severity: AnalysisSeverity, title: str, description: str) -> SecurityFinding:
        """Create a security finding for vulnerabilities of a specific severity"""
        
        evidence = []
        cve_references = []
        
        for vuln in vulnerabilities[:10]:  # Limit to first 10 for readability
            evidence_line = f"{vuln.cve_id}"
            if vuln.cvss_score:
                evidence_line += f" (CVSS: {vuln.cvss_score})"
            evidence_line += f": {vuln.summary[:100]}..."
            evidence.append(evidence_line)
            
            # Collect unique references
            for ref in vuln.references[:2]:  # Limit references per CVE
                if ref not in cve_references:
                    cve_references.append(ref)
        
        if len(vulnerabilities) > 10:
            evidence.append(f"... and {len(vulnerabilities) - 10} more vulnerabilities")
        
        recommendations = [
            "Immediately update affected libraries to patched versions",
            "Review CVE details and assess impact on your application",
            "Implement workarounds if patches are not immediately available",
            "Monitor security advisories for additional updates",
            "Consider security testing for affected functionality"
        ]
        
        if severity == AnalysisSeverity.CRITICAL:
            recommendations.insert(0, "URGENT: Address critical vulnerabilities immediately")
            recommendations.append("Consider temporarily disabling affected features if necessary")
        
        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations
        )
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get CVE scanning statistics"""
        stats = {
            'clients_initialized': len(self.clients),
            'cache_stats': self.cache_manager.get_cache_stats() if self.cache_manager else {},
            'sources_enabled': [source for source, config in self.sources_config.items() 
                              if config.get('enabled', False)],
        }
        
        # Get rate limit status from clients
        for source, client in self.clients.items():
            try:
                stats[f'{source}_rate_limit'] = client.get_rate_limit_status()
            except Exception as e:
                self.logger.debug(f"Could not get rate limit status for {source}: {e}")
        
        return stats