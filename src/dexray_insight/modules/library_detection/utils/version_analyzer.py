#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Version Analysis Utilities for Library Detection

Provides version comparison, parsing, and age calculation functionality
for determining how outdated detected libraries are.
"""

import re
import logging
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, Any
from dataclasses import dataclass
from packaging import version


@dataclass
class VersionInfo:
    """Information about a library version"""
    version: str
    release_date: Optional[datetime] = None
    is_latest: bool = False
    is_prerelease: bool = False
    vulnerability_count: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary with JSON-serializable values"""
        return {
            'version': self.version,
            'release_date': self.release_date.isoformat() if self.release_date else None,
            'is_latest': self.is_latest,
            'is_prerelease': self.is_prerelease,
            'vulnerability_count': self.vulnerability_count
        }


@dataclass 
class VersionAnalysisResult:
    """Result of version analysis for a library"""
    current_version: str
    latest_version: Optional[str] = None
    years_behind: Optional[float] = None
    major_versions_behind: Optional[int] = None
    security_risk: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    recommendation: str = ""
    analysis_date: datetime = None
    
    def __post_init__(self):
        if self.analysis_date is None:
            self.analysis_date = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert to dictionary with JSON-serializable values"""
        return {
            'current_version': self.current_version,
            'latest_version': self.latest_version,
            'years_behind': self.years_behind,
            'major_versions_behind': self.major_versions_behind,
            'security_risk': self.security_risk,
            'recommendation': self.recommendation,
            'analysis_date': self.analysis_date.isoformat() if self.analysis_date else None
        }


class VersionAnalyzer:
    """
    Analyzes library versions to determine how outdated they are and calculate security risks.
    
    Supports multiple version sources:
    - Maven Central API for Android/Java libraries
    - npm registry for JavaScript libraries  
    - PyPI API for Python libraries
    - Custom version databases
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None, security_analysis_enabled: bool = False):
        self.logger = logger or logging.getLogger(__name__)
        self.config = config.get('version_analysis', {})
        
        # Configuration options
        self.enable_version_checking = self.config.get('enabled', True)
        self.security_analysis_only = self.config.get('security_analysis_only', True)
        self.security_analysis_enabled = security_analysis_enabled
        self.api_timeout = self.config.get('api_timeout', 10)
        self.cache_duration = self.config.get('cache_duration_hours', 24)
        
        # Version cache to avoid repeated API calls
        self._version_cache: Dict[str, VersionInfo] = {}
        self._cache_timestamps: Dict[str, datetime] = {}
        
        # Known library version sources
        self.version_sources = {
            'maven': self._check_maven_central,
            'npm': self._check_npm_registry,
            'pypi': self._check_pypi,
            'custom': self._check_custom_database
        }
        
    def analyze_library_version(self, library_name: str, current_version: str, 
                               package_name: Optional[str] = None) -> VersionAnalysisResult:
        """
        Analyze a library version to determine how outdated it is.
        
        Args:
            library_name: Human-readable library name
            current_version: Current version found in the app
            package_name: Package identifier (e.g., com.example.library)
            
        Returns:
            VersionAnalysisResult with analysis information
        """
        if not self.enable_version_checking:
            return VersionAnalysisResult(
                current_version=current_version,
                recommendation="Version checking disabled in configuration"
            )
            
        # Check if version analysis should only run during security analysis
        if self.security_analysis_only and not self.security_analysis_enabled:
            self.logger.info(f"🚫 VERSION ANALYSIS SKIPPED: {library_name} - security analysis only mode, security not enabled")
            return VersionAnalysisResult(
                current_version=current_version,
                recommendation="Version analysis only runs during security analysis (use -s flag)"
            )
        
        self.logger.info(f"✅ VERSION ANALYSIS RUNNING: {library_name} v{current_version} (security_only={self.security_analysis_only}, security_enabled={self.security_analysis_enabled})")
            
        try:
            # Normalize version string
            normalized_current = self._normalize_version(current_version)
            if not normalized_current:
                return VersionAnalysisResult(
                    current_version=current_version,
                    recommendation="Unable to parse version format"
                )
            
            # Get latest version information
            latest_info = self._get_latest_version_info(library_name, package_name)
            if not latest_info:
                return VersionAnalysisResult(
                    current_version=current_version,
                    recommendation="Unable to determine latest version"
                )
            
            # Calculate version difference
            years_behind = self._calculate_years_behind(
                normalized_current, latest_info.version, latest_info.release_date
            )
            
            major_versions_behind = self._calculate_major_versions_behind(
                normalized_current, latest_info.version
            )
            
            # Determine security risk and recommendation
            security_risk, recommendation = self._assess_security_risk(
                years_behind, major_versions_behind, latest_info.vulnerability_count
            )
            
            return VersionAnalysisResult(
                current_version=current_version,
                latest_version=latest_info.version,
                years_behind=years_behind,
                major_versions_behind=major_versions_behind,
                security_risk=security_risk,
                recommendation=recommendation
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing version for {library_name}: {e}")
            return VersionAnalysisResult(
                current_version=current_version,
                recommendation=f"Version analysis failed: {str(e)}"
            )
    
    def _normalize_version(self, version_str: str) -> Optional[str]:
        """
        Normalize version string to semantic version format.
        
        Handles various version formats:
        - 1.2.3
        - 1.2.3-alpha
        - 1.2.3.4 -> 1.2.3
        - v1.2.3 -> 1.2.3
        """
        if not version_str:
            return None
            
        # Remove common prefixes
        cleaned = re.sub(r'^[vV]', '', version_str.strip())
        
        # Extract semantic version pattern
        semantic_pattern = r'(\d+)\.(\d+)\.(\d+)(?:[-\.].*)?'
        match = re.match(semantic_pattern, cleaned)
        
        if match:
            major, minor, patch = match.groups()
            return f"{major}.{minor}.{patch}"
        
        # Try simpler patterns
        simple_pattern = r'(\d+)\.(\d+)'
        match = re.match(simple_pattern, cleaned)
        if match:
            major, minor = match.groups()
            return f"{major}.{minor}.0"
            
        # Single number version
        if cleaned.isdigit():
            return f"{cleaned}.0.0"
            
        return None
    
    def _get_latest_version_info(self, library_name: str, 
                                package_name: Optional[str] = None) -> Optional[VersionInfo]:
        """Get latest version information from various sources"""
        cache_key = package_name or library_name
        
        # Check cache first
        if self._is_cached_valid(cache_key):
            return self._version_cache[cache_key]
        
        # Try Google Maven Repository FIRST for Google Play Services and Firebase
        google_version = self._check_google_maven(library_name, package_name)
        if google_version:
            self._version_cache[cache_key] = google_version
            self._cache_timestamps[cache_key] = datetime.now()
            return google_version
        
        # Try other version sources
        for source_name, source_func in self.version_sources.items():
            try:
                version_info = source_func(library_name, package_name)
                if version_info:
                    # Cache the result
                    self._version_cache[cache_key] = version_info
                    self._cache_timestamps[cache_key] = datetime.now()
                    return version_info
            except Exception as e:
                self.logger.debug(f"Failed to get version from {source_name}: {e}")
                continue
        
        return None
    
    def _check_maven_central(self, library_name: str, 
                            package_name: Optional[str] = None) -> Optional[VersionInfo]:
        """Check Maven Central for latest version using improved mapping"""
        try:
            # Import library mappings
            from .library_mappings import get_maven_coordinates
            
            # Try to get proper Maven coordinates from mapping
            maven_coords = get_maven_coordinates(library_name)
            
            if maven_coords:
                group_id, artifact_id = maven_coords.split(':', 1)
                self.logger.debug(f"Using Maven coordinates from mapping: {group_id}:{artifact_id}")
            elif package_name:
                # Fallback to package_name parsing
                if '.' in package_name:
                    parts = package_name.split('.')
                    group_id = '.'.join(parts[:-1])
                    artifact_id = parts[-1]
                else:
                    group_id = package_name
                    artifact_id = library_name.lower().replace(' ', '-')
                self.logger.debug(f"Using fallback Maven coordinates: {group_id}:{artifact_id}")
            else:
                # Last resort: try common patterns
                if library_name.startswith('play-services-'):
                    group_id = 'com.google.android.gms'
                    artifact_id = library_name
                elif library_name.startswith('firebase-'):
                    group_id = 'com.google.firebase' 
                    artifact_id = library_name
                elif library_name in ['billing']:
                    group_id = 'com.android.billingclient'
                    artifact_id = library_name
                else:
                    self.logger.debug(f"No Maven mapping found for {library_name}")
                    return None
            
            # Maven Central API with multiple search strategies
            strategies = [
                # Strategy 1: Exact group and artifact match
                f'g:"{group_id}" AND a:"{artifact_id}"',
                # Strategy 2: Group wildcard - fixed syntax
                f'g:{group_id}* AND a:{artifact_id}',
                # Strategy 3: Artifact name only
                f'a:"{artifact_id}"'
            ]
            
            for i, query in enumerate(strategies):
                self.logger.debug(f"Maven Central strategy {i+1}: {query}")
                
                url = "https://search.maven.org/solrsearch/select"
                params = {
                    'q': query,
                    'rows': 5,  # Get more results for better matching
                    'wt': 'json',
                    'sort': 'timestamp desc'  # Get most recent first
                }
                
                response = requests.get(url, params=params, timeout=self.api_timeout)
                response.raise_for_status()
                
                data = response.json()
                docs = data.get('response', {}).get('docs', [])
                
                if docs:
                    # Find best match (prefer exact group match)
                    best_doc = None
                    for doc in docs:
                        doc_group = doc.get('g', '')
                        doc_artifact = doc.get('a', '')
                        
                        # Exact match is best
                        if doc_group == group_id and doc_artifact == artifact_id:
                            best_doc = doc
                            break
                        # Partial group match is acceptable
                        elif group_id in doc_group and doc_artifact == artifact_id:
                            if not best_doc:
                                best_doc = doc
                    
                    if not best_doc:
                        best_doc = docs[0]  # Use first result as fallback
                    
                    latest_version = best_doc.get('latestVersion')
                    timestamp = best_doc.get('timestamp')
                    
                    release_date = None
                    if timestamp:
                        release_date = datetime.fromtimestamp(timestamp / 1000)
                    
                    self.logger.debug(f"Maven Central found: {best_doc.get('g')}:{best_doc.get('a')}:{latest_version}")
                    
                    return VersionInfo(
                        version=latest_version,
                        release_date=release_date,
                        is_latest=True
                    )
                
        except Exception as e:
            self.logger.debug(f"Maven Central API failed: {e}")
            
        return None
    
    def _check_npm_registry(self, library_name: str, 
                           package_name: Optional[str] = None) -> Optional[VersionInfo]:
        """Check npm registry for JavaScript libraries"""
        # Try multiple name variations for better matching
        search_names = [
            package_name or library_name.lower().replace(' ', '-'),
            library_name.lower().replace(' ', ''),
            library_name.lower().replace('-', ''),
            f"@{library_name.lower().replace(' ', '-')}"  # Scoped packages
        ]
        
        for search_name in search_names:
            try:
                # Try both /latest and base URL approaches
                for url_pattern in [f"https://registry.npmjs.org/{search_name}/latest", f"https://registry.npmjs.org/{search_name}"]:
                    response = requests.get(url_pattern, timeout=self.api_timeout)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Handle different response formats
                        if 'version' in data:
                            latest_version = data['version']
                        elif 'dist-tags' in data and 'latest' in data['dist-tags']:
                            latest_version = data['dist-tags']['latest']
                        else:
                            continue
                            
                        if latest_version:
                            self.logger.debug(f"npm found: {search_name} -> {latest_version}")
                            return VersionInfo(
                                version=latest_version,
                                is_latest=True
                            )
                    
            except Exception as e:
                self.logger.debug(f"npm registry API failed for {search_name}: {e}")
                continue
            
        return None
    
    def _check_pypi(self, library_name: str, 
                   package_name: Optional[str] = None) -> Optional[VersionInfo]:
        """Check PyPI for Python libraries (in case of Kivy/BeeWare apps)"""
        search_name = package_name or library_name.lower().replace(' ', '-')
        
        try:
            url = f"https://pypi.org/pypi/{search_name}/json"
            response = requests.get(url, timeout=self.api_timeout)
            
            if response.status_code == 200:
                data = response.json()
                latest_version = data['info']['version']
                
                return VersionInfo(
                    version=latest_version,
                    is_latest=True
                )
                
        except Exception as e:
            self.logger.debug(f"PyPI API failed: {e}")
            
        return None
    
    def _check_custom_database(self, library_name: str, 
                              package_name: Optional[str] = None) -> Optional[VersionInfo]:
        """Check custom version database (could be extended with local database)"""
        # This could be extended to use a local database or custom API
        # For now, return None to indicate no custom database
        return None
    
    def _check_google_maven(self, library_name: str, 
                           package_name: Optional[str] = None) -> Optional[VersionInfo]:
        """
        Check Google Maven Repository for Play Services and Firebase libraries.
        
        Google maintains their own Maven repository at:
        https://maven.google.com/
        
        This includes:
        - Google Play Services (com.google.android.gms)
        - Firebase (com.google.firebase)
        - AndroidX (androidx.*)
        - Android Support Library (com.android.support)
        """
        self.logger.debug(f"Google Maven: Called with library_name='{library_name}', package_name='{package_name}'")
        
        try:
            from .library_mappings import get_library_mapping
            
            # Get proper Maven coordinates
            mapping = get_library_mapping(library_name)
            if not mapping:
                self.logger.debug(f"Google Maven: No mapping found for '{library_name}' (exact name)")
                
                # Try alternative names if available
                if package_name:
                    self.logger.debug(f"Google Maven: Trying package_name '{package_name}' as library name")
                    mapping = get_library_mapping(package_name)
                    if mapping:
                        self.logger.debug(f"Google Maven: Found mapping using package_name '{package_name}'")
                
                if not mapping:
                    self.logger.debug(f"Google Maven: No mapping found for library_name='{library_name}' or package_name='{package_name}'")
                    return None
                
            group_id = mapping.maven_group_id
            artifact_id = mapping.maven_artifact_id
            
            self.logger.debug(f"Google Maven: Found mapping {library_name} -> {group_id}:{artifact_id}")
            
            # Check if this is a Google-maintained library
            google_groups = [
                'com.google.android.gms',
                'com.google.firebase', 
                'androidx.',
                'com.android.support',
                'com.google.android.play',
                'com.android.billingclient'
            ]
            
            if not any(group_id.startswith(prefix) for prefix in google_groups):
                self.logger.debug(f"Google Maven: {group_id} not a Google library, skipping")
                return None
            
            self.logger.debug(f"Google Maven: {group_id} is Google library, proceeding with analysis")
                
            # Use Google Maven repository index
            # Format: https://maven.google.com/web/index.html?q={group_id}:{artifact_id}
            # But we need to use the raw JSON API
            
            # Google Maven uses a different structure - try their group listing
            group_path = group_id.replace('.', '/')
            
            try:
                # Try to get the artifact listing from Google Maven
                url = f"https://maven.google.com/{group_path}/{artifact_id}/maven-metadata.xml"
                response = requests.get(url, timeout=self.api_timeout)
                
                if response.status_code == 200:
                    # Parse XML to get latest version
                    import xml.etree.ElementTree as ET
                    
                    root = ET.fromstring(response.text)
                    versioning = root.find('versioning')
                    
                    if versioning is not None:
                        latest = versioning.find('latest')
                        release = versioning.find('release') 
                        
                        # Prefer 'release' over 'latest' (release excludes snapshots/betas)
                        latest_version = None
                        if release is not None and release.text:
                            latest_version = release.text
                        elif latest is not None and latest.text:
                            latest_version = latest.text
                            
                        if latest_version:
                            self.logger.debug(f"Google Maven found: {group_id}:{artifact_id} -> {latest_version}")
                            return VersionInfo(
                                version=latest_version,
                                is_latest=True
                            )
                            
            except Exception as inner_e:
                self.logger.debug(f"Google Maven XML API failed: {inner_e}")
                
            # Fallback: Try to use known version patterns for major Google libraries
            return self._get_known_google_versions(group_id, artifact_id)
                
        except Exception as e:
            self.logger.debug(f"Google Maven API failed: {e}")
            
        return None
    
    def _get_known_google_versions(self, group_id: str, artifact_id: str) -> Optional[VersionInfo]:
        """
        Fallback method with known latest versions for major Google libraries.
        
        This is updated manually with known stable versions as of early 2025.
        """
        known_versions = {
            # Google Play Services (as of early 2025)
            'com.google.android.gms:play-services-base': '18.6.0',
            'com.google.android.gms:play-services-basement': '18.6.0', 
            'com.google.android.gms:play-services-tasks': '18.6.0',
            'com.google.android.gms:play-services-auth': '21.4.0',
            'com.google.android.gms:play-services-location': '21.4.0',
            'com.google.android.gms:play-services-maps': '19.0.0',
            'com.google.android.gms:play-services-cast': '21.6.0',
            'com.google.android.gms:play-services-vision': '20.1.3',
            'com.google.android.gms:play-services-ads-identifier': '18.1.0',
            
            # Firebase (as of early 2025)
            'com.google.firebase:firebase-messaging': '24.1.0',
            'com.google.firebase:firebase-common': '21.0.0',
            'com.google.firebase:firebase-components': '18.0.0',
            'com.google.firebase:firebase-analytics': '22.1.2',
            'com.google.firebase:firebase-auth': '23.1.0',
            'com.google.firebase:firebase-measurement-connector': '22.1.0',
            'com.google.firebase:firebase-iid': '21.1.0',
            'com.google.firebase:firebase-iid-interop': '17.1.0',
            'com.google.firebase:firebase-annotations': '16.2.0',
            
            # AndroidX Core (as of early 2025)
            'androidx.arch.core:core-common': '2.2.0',
            'androidx.core:core': '1.15.0',
            'androidx.appcompat:appcompat': '1.7.0',
            
            # Google Play Services for Android (as of early 2025)
            'com.google.android.play:app-update': '2.2.0',
            'com.google.android.play:review': '2.1.0',
            'com.google.android.play:integrity': '1.4.0',
            
            # Billing
            'com.android.billingclient:billing': '7.2.0'
        }
        
        coord = f"{group_id}:{artifact_id}"
        if coord in known_versions:
            latest_version = known_versions[coord]
            self.logger.debug(f"Using known version for {coord}: {latest_version}")
            return VersionInfo(
                version=latest_version,
                is_latest=True
            )
        else:
            self.logger.debug(f"No known version for {coord}")
            
        return None
    
    def _calculate_years_behind(self, current_version: str, latest_version: str, 
                               release_date: Optional[datetime]) -> Optional[float]:
        """Calculate how many years behind the current version is"""
        try:
            current_ver = version.parse(current_version)
            latest_ver = version.parse(latest_version)
            
            if current_ver >= latest_ver:
                return 0.0
            
            if release_date:
                # Use actual release date
                time_diff = datetime.now() - release_date
                return round(time_diff.days / 365.25, 1)
            else:
                # Estimate based on version difference (very rough)
                major_diff = latest_ver.major - current_ver.major
                minor_diff = latest_ver.minor - current_ver.minor
                
                # Rough estimation: major version ~ 1 year, minor version ~ 3 months
                estimated_years = major_diff * 1.0 + minor_diff * 0.25
                return round(max(estimated_years, 0.1), 1)
                
        except Exception as e:
            self.logger.debug(f"Error calculating years behind: {e}")
            return None
    
    def _calculate_major_versions_behind(self, current_version: str, 
                                       latest_version: str) -> Optional[int]:
        """Calculate how many major versions behind"""
        try:
            current_ver = version.parse(current_version)
            latest_ver = version.parse(latest_version)
            
            return max(0, latest_ver.major - current_ver.major)
            
        except Exception:
            return None
    
    def _assess_security_risk(self, years_behind: Optional[float], 
                            major_versions_behind: Optional[int],
                            vulnerability_count: int) -> Tuple[str, str]:
        """Assess security risk and provide recommendation"""
        if not years_behind:
            return "UNKNOWN", "Unable to determine version age"
        
        # Base risk assessment on age
        if years_behind >= 3.0:
            risk = "CRITICAL"
            recommendation = f"Extremely outdated ({years_behind} years behind). Update immediately for security."
        elif years_behind >= 2.0:
            risk = "HIGH" 
            recommendation = f"Very outdated ({years_behind} years behind). High priority update recommended."
        elif years_behind >= 1.0:
            risk = "MEDIUM"
            recommendation = f"Outdated ({years_behind} years behind). Update recommended."
        elif years_behind >= 0.5:
            risk = "LOW"
            recommendation = f"Slightly outdated ({years_behind} years behind). Consider updating."
        else:
            risk = "LOW"
            recommendation = "Version is relatively current."
        
        # Escalate risk if many major versions behind
        if major_versions_behind and major_versions_behind >= 3:
            if risk in ["LOW", "MEDIUM"]:
                risk = "HIGH"
                recommendation += f" ({major_versions_behind} major versions behind)"
        
        # Factor in known vulnerabilities
        if vulnerability_count > 0:
            if risk == "LOW":
                risk = "MEDIUM"
            elif risk == "MEDIUM": 
                risk = "HIGH"
            recommendation += f" {vulnerability_count} known vulnerabilities."
            
        return risk, recommendation
    
    def _is_cached_valid(self, cache_key: str) -> bool:
        """Check if cached version info is still valid"""
        if cache_key not in self._version_cache:
            return False
            
        cache_time = self._cache_timestamps.get(cache_key)
        if not cache_time:
            return False
            
        age = datetime.now() - cache_time
        return age < timedelta(hours=self.cache_duration)
    
    def format_version_output(self, library_name: str, analysis: VersionAnalysisResult, 
                             smali_path: str = "") -> str:
        """
        Format version analysis output for console display.
        
        Format: library name (version): smali path : years behind
        Example: Gson (2.8.5): /com/google/gson/ : 2.1 years behind
        """
        path_part = f": {smali_path} " if smali_path else ""
        
        if analysis.years_behind is not None:
            years_part = f": {analysis.years_behind} years behind"
            
            # Add security risk indicator
            risk_indicator = ""
            if analysis.security_risk == "CRITICAL":
                risk_indicator = " ⚠️ CRITICAL"
            elif analysis.security_risk == "HIGH": 
                risk_indicator = " ⚠️ HIGH RISK"
            elif analysis.security_risk == "MEDIUM":
                risk_indicator = " ⚠️ MEDIUM RISK"
                
            return f"{library_name} ({analysis.current_version}){path_part}{years_part}{risk_indicator}"
        else:
            return f"{library_name} ({analysis.current_version}){path_part}: version analysis unavailable"


# Global instance for easy access
_version_analyzer: Optional[VersionAnalyzer] = None


def get_version_analyzer(config: Dict[str, Any] = None, security_analysis_enabled: bool = False) -> VersionAnalyzer:
    """Get global version analyzer instance"""
    global _version_analyzer
    # Always create a new instance if security context or config changes
    if (_version_analyzer is None or 
        config or 
        (hasattr(_version_analyzer, 'security_analysis_enabled') and 
         _version_analyzer.security_analysis_enabled != security_analysis_enabled)):
        _version_analyzer = VersionAnalyzer(config or {}, security_analysis_enabled=security_analysis_enabled)
    return _version_analyzer