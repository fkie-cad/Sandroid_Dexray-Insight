#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apktool-based Library Detection Engine

This engine integrates the functionality from detect_libs.py, requiring apktool
extraction to analyze smali directories and other extracted files for library detection.
Implements three detection approaches:
1. Pattern-based detection using IzzyOnDroid JSONL files
2. Properties file analysis
3. BuildConfig.smali analysis
"""

import os
import re
import json
import time
import logging
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional

from dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryDetectionMethod, LibraryCategory, 
    LibraryType, RiskLevel, LibrarySource
)
from ..utils.version_analyzer import get_version_analyzer


class ApktoolDetectionEngine:
    """
    Library detection engine that requires apktool extraction results.
    Integrates three detection approaches from detect_libs.py.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize ApktoolDetectionEngine with configuration.
        
        Args:
            config: Configuration dictionary containing apktool_detection settings
            logger: Optional logger instance for logging messages
            
        Raises:
            ValueError: If configuration contains invalid values
        """
        self.logger = logger or logging.getLogger(__name__)
        self.config = config.get('apktool_detection', {})
        
        # Configuration for IzzyOnDroid library definitions
        self.enable_pattern_detection = self.config.get('enable_pattern_detection', True)
        self.enable_properties_detection = self.config.get('enable_properties_detection', True) 
        self.enable_buildconfig_detection = self.config.get('enable_buildconfig_detection', True)
        
        # URLs for library definitions (can be overridden in config)
        self.libsmali_url = self.config.get('libsmali_url', 
            'https://gitlab.com/IzzyOnDroid/repo/-/raw/master/lib/libsmali.jsonl')
        self.libinfo_url = self.config.get('libinfo_url',
            'https://gitlab.com/IzzyOnDroid/repo/-/raw/master/lib/libinfo.jsonl')
        
        # Local file paths (can be overridden in config)
        self.libsmali_path = self.config.get('libsmali_path', './libsmali.jsonl')
        self.libinfo_path = self.config.get('libinfo_path', './libinfo.jsonl')
        
        # Cache for library definitions
        self._libs_by_path: Optional[Dict[str, dict]] = None
        self._id_to_paths: Optional[Dict[str, List[str]]] = None
        
        # Initialize version analyzer (will be updated with security context later)
        self.version_analyzer = get_version_analyzer(config)
        
        # Check for newer library definitions on startup
        if self.config.get('auto_update_definitions', True):
            self._update_library_definitions()
    
    def is_available(self, context) -> bool:
        """
        Check if apktool extraction results are available for analysis.
        
        Args:
            context: Analysis context containing temporal paths
            
        Returns:
            True if apktool extraction results are available and non-empty, False otherwise
            
        Note:
            This method ensures that apktool has been successfully executed and
            produced extraction results before attempting library detection.
        """
        temporal_paths = getattr(context, 'temporal_paths', None)
        if not temporal_paths:
            return False
        
        apktool_dir = temporal_paths.apktool_dir
        return apktool_dir and apktool_dir.exists() and any(apktool_dir.iterdir())
    
    def detect_libraries(self, context, errors: List[str]) -> List[DetectedLibrary]:
        """
        Main detection method that orchestrates all three approaches
        
        Args:
            context: Analysis context with temporal directory paths
            errors: List to append any analysis errors
            
        Returns:
            List of detected libraries from all approaches
        """
        if not self.is_available(context):
            errors.append("Apktool extraction results not available for library detection")
            return []
        
        # IMPORTANT: Update version analyzer with security context BEFORE any detection phases
        # This ensures that _enhance_library_with_version_analysis calls use the correct security context
        security_analysis_enabled = context.config.get('security', {}).get('enable_owasp_assessment', False)
        full_config = dict(self.config)
        full_config.update(context.config.get('modules', {}).get('library_detection', {}))
        self.version_analyzer = get_version_analyzer(
            {'version_analysis': full_config.get('version_analysis', {})}, 
            security_analysis_enabled=security_analysis_enabled
        )
        
        self.logger.debug(f"Version analyzer configured: security_analysis_enabled={security_analysis_enabled}, "
                         f"security_analysis_only={self.version_analyzer.security_analysis_only}, "
                         f"version_analysis_enabled={self.version_analyzer.enable_version_checking}")
        
        detected_libraries = []
        temporal_paths = context.temporal_paths
        apktool_dir = temporal_paths.apktool_dir
        
        start_time = time.time()
        
        try:
            # Approach 1: Pattern-based detection using JSONL files
            if self.enable_pattern_detection:
                pattern_libraries = self._scan_lib_patterns(apktool_dir, errors)
                detected_libraries.extend(pattern_libraries)
                self.logger.debug(f"Pattern detection found {len(pattern_libraries)} libraries")
            
            # Approach 2: Properties file analysis
            if self.enable_properties_detection:
                properties_libraries = self._scan_properties(apktool_dir, errors)
                detected_libraries.extend(properties_libraries)
                self.logger.debug(f"Properties detection found {len(properties_libraries)} libraries")
            
            # Approach 3: BuildConfig.smali analysis
            if self.enable_buildconfig_detection:
                buildconfig_libraries = self._scan_buildconfig_smali(apktool_dir, errors)
                detected_libraries.extend(buildconfig_libraries)
                self.logger.debug(f"BuildConfig detection found {len(buildconfig_libraries)} libraries")
            
            # Deduplicate results
            detected_libraries = self._deduplicate_libraries(detected_libraries)
            
            analysis_time = time.time() - start_time
            self.logger.info(f"Apktool detection completed in {analysis_time:.2f}s: {len(detected_libraries)} libraries")
            
            # Version analysis printing moved to main library detection module for proper ordering
            
        except Exception as e:
            error_msg = f"Error in apktool-based library detection: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        return detected_libraries
    
    def _update_library_definitions(self):
        """
        Download newer library definitions from IzzyOnDroid repository if available.
        
        This method checks if local library definition files (libsmali.jsonl and libinfo.jsonl)
        need to be updated from the IzzyOnDroid repository. Updates are performed if:
        - Local files don't exist, or
        - Local files are older than 7 days
        
        Raises:
            requests.RequestException: If download fails
            IOError: If file writing fails
        """
        try:
            # Check libsmali.jsonl
            if self._should_update_file(self.libsmali_path, self.libsmali_url):
                self._download_file(self.libsmali_url, self.libsmali_path)
                self.logger.info(f"Updated {self.libsmali_path} from {self.libsmali_url}")
            
            # Check libinfo.jsonl  
            if self._should_update_file(self.libinfo_path, self.libinfo_url):
                self._download_file(self.libinfo_url, self.libinfo_path)
                self.logger.info(f"Updated {self.libinfo_path} from {self.libinfo_url}")
                
        except Exception as e:
            self.logger.warning(f"Failed to update library definitions: {e}")
    
    def _should_update_file(self, local_path: str, url: str) -> bool:
        """Check if local file should be updated from remote URL"""
        if not os.path.exists(local_path):
            return True
        
        # Check file age (update if older than 7 days)
        local_mtime = os.path.getmtime(local_path)
        age_days = (time.time() - local_mtime) / (24 * 3600)
        
        return age_days > 7
    
    def _download_file(self, url: str, local_path: str):
        """Download file from URL to local path"""
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        
        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
    
    def _load_library_definitions(self):
        """Load library definitions from JSONL files"""
        if self._libs_by_path is not None:
            return  # Already loaded
        
        self._libs_by_path = {}
        self._id_to_paths = {}
        
        # Load libsmali.jsonl
        try:
            libsmali_entries = self._load_jsonl(self.libsmali_path)
            for entry in libsmali_entries:
                path_key = entry.get("path")
                if not path_key:
                    continue
                self._libs_by_path[path_key] = dict(entry)
                lib_id = entry.get("id")
                if lib_id:
                    self._id_to_paths.setdefault(lib_id, []).append(path_key)
                    
        except FileNotFoundError:
            self.logger.warning(f"libsmali.jsonl not found at {self.libsmali_path}")
        except Exception as e:
            self.logger.error(f"Error loading libsmali.jsonl: {e}")
        
        # Load libinfo.jsonl and merge with libsmali data
        try:
            libinfo_entries = self._load_jsonl(self.libinfo_path)
            for entry in libinfo_entries:
                lib_id = entry.get("id")
                if not lib_id or lib_id not in self._id_to_paths:
                    continue
                
                # Merge info into all paths with this ID
                for path_key in self._id_to_paths[lib_id]:
                    target = self._libs_by_path.get(path_key)
                    if not target:
                        continue
                    
                    # Add details, anti-features, and license info
                    if "details" in entry:
                        target["details"] = entry["details"]
                    if "anti" in entry:
                        target["anti"] = entry.get("anti") or []
                    if "license" in entry:
                        target["license"] = entry["license"]
                        
        except FileNotFoundError:
            self.logger.warning(f"libinfo.jsonl not found at {self.libinfo_path}")
        except Exception as e:
            self.logger.error(f"Error loading libinfo.jsonl: {e}")
    
    def _load_jsonl(self, path: str) -> List[dict]:
        """Load JSONL file robustly"""
        items = []
        with open(path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        items.append(obj)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse line {line_no} in {path}: {e}")
        return items
    
    def _find_smali_roots(self, apktool_dir: Path) -> List[Path]:
        """Find all smali* directories in apktool output"""
        smali_roots = []
        try:
            for item in apktool_dir.iterdir():
                if item.is_dir() and item.name.startswith("smali"):
                    smali_roots.append(item)
        except Exception as e:
            self.logger.error(f"Error finding smali roots: {e}")
        return smali_roots
    
    def _lib_dir_exists(self, apktool_dir: Path, lib_path: str) -> bool:
        """Check if library path exists in any smali root directory"""
        smali_roots = self._find_smali_roots(apktool_dir)
        if not smali_roots:
            self.logger.debug(f"No smali roots found in {apktool_dir}")
            return False
        
        # Normalize lib_path (remove leading slash)
        rel_path = lib_path.lstrip("/")
        
        for smali_root in smali_roots:
            candidate = smali_root / Path(rel_path.replace("/", os.sep))
            if candidate.exists() and candidate.is_dir():
                self.logger.debug(f"Found library path {lib_path} in {smali_root}")
                return True
            else:
                # Debug missing paths for AndroidX only
                if "androidx" in lib_path.lower():
                    self.logger.debug(f"AndroidX path not found: {candidate} (from {lib_path})")
        
        return False
    
    def _scan_lib_patterns(self, apktool_dir: Path, errors: List[str]) -> List[DetectedLibrary]:
        """
        Scan for libraries using pattern matching against IzzyOnDroid JSONL definitions.
        
        This method implements the first detection approach from detect_libs.py,
        checking if known library paths exist in the extracted smali directories.
        
        Args:
            apktool_dir: Path to apktool extraction directory
            errors: List to append any error messages encountered
            
        Returns:
            List of DetectedLibrary objects found through pattern matching
            
        Note:
            Requires libsmali.jsonl and libinfo.jsonl files to be available.
            These files contain library path patterns and metadata.
        """
        detected_libraries = []
        
        try:
            self._load_library_definitions()
            
            if not self._libs_by_path:
                errors.append("No library patterns loaded for pattern detection")
                return detected_libraries
            
            # Count AndroidX patterns for debugging
            androidx_patterns = [path for path in self._libs_by_path.keys() if "androidx" in path.lower()]
            self.logger.debug(f"Total AndroidX patterns in libsmali.jsonl: {len(androidx_patterns)}")
            
            # Check each library pattern against smali directories
            for lib_path, definition in self._libs_by_path.items():
                if self._lib_dir_exists(apktool_dir, lib_path):
                    # Debug AndroidX finds
                    if "androidx" in lib_path.lower():
                        self.logger.debug(f"AndroidX pattern MATCHED: {lib_path} -> {definition.get('name', 'unknown')}")
                    
                    library = self._create_detected_library_from_definition(
                        definition, LibraryDetectionMethod.PATTERN_MATCHING, lib_path
                    )
                    if library:
                        # Debug AndroidX library creation
                        if "androidx" in lib_path.lower():
                            self.logger.debug(f"AndroidX library CREATED: {library.name} (Category: {library.category.name})")
                        # Enhance library with version analysis if version is available
                        if library.version:
                            self._enhance_library_with_version_analysis(library)
                        detected_libraries.append(library)
                        # Debug AndroidX library addition to list
                        if "androidx" in lib_path.lower():
                            # Filter by smali_path containing androidx, not by name!
                            current_androidx = [lib.name for lib in detected_libraries if hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path]
                            self.logger.debug(f"AndroidX ADDED to list: {library.name} (List now has {len(current_androidx)} AndroidX libs: {current_androidx})")
                    else:
                        # Debug failed library creation
                        if "androidx" in lib_path.lower():
                            self.logger.debug(f"AndroidX library CREATION FAILED for {lib_path} -> {definition.get('name', 'unknown')}")
                elif "androidx" in lib_path.lower():
                    # Debug AndroidX misses
                    self.logger.debug(f"AndroidX pattern NOT found: {lib_path}")
                        
        except Exception as e:
            error_msg = f"Error in pattern-based library detection: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        # Final debug before return
        final_androidx = [lib for lib in detected_libraries if hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path]
        self.logger.debug(f"FINAL RETURN: {len(detected_libraries)} total libraries, {len(final_androidx)} AndroidX")
        
        return detected_libraries
    
    def _scan_properties(self, apktool_dir: Path, errors: List[str]) -> List[DetectedLibrary]:
        """Scan for .properties files containing library version information"""
        detected_libraries = []
        
        try:
            for properties_file in apktool_dir.rglob("*.properties"):
                try:
                    version = None
                    client = None
                    
                    with open(properties_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line or "=" not in line:
                                continue
                            key, val = line.split("=", 1)
                            if key.strip() == "version":
                                version = val.strip()
                            elif key.strip() == "client":
                                client = val.strip()
                    
                    if client and version:
                        # Try to get enhanced library information from mapping
                        from ..utils.library_mappings import get_library_mapping
                        
                        mapping = get_library_mapping(client)
                        display_name = mapping.display_name if mapping else client
                        category_str = mapping.category if mapping else "unknown"
                        description = mapping.description if mapping else ""
                        url = mapping.official_url if mapping else ""
                        
                        # Map category string to enum
                        category = self._map_category_string_to_enum(category_str)
                        
                        library = DetectedLibrary(
                            name=display_name,
                            package_name=client,
                            version=version,
                            detection_method=LibraryDetectionMethod.FILE_ANALYSIS,
                            category=category,
                            confidence=0.9,
                            evidence=[f"Found in properties file: {properties_file.name}"],
                            file_paths=[str(properties_file.relative_to(apktool_dir))],
                            source=LibrarySource.PROPERTIES_FILES,
                            smali_path=str(properties_file.relative_to(apktool_dir)),
                            url=url
                        )
                        
                        # Add description to evidence if available
                        if description:
                            library.evidence.append(f"Description: {description}")
                        
                        # Enhance with version analysis
                        self._enhance_library_with_version_analysis(library)
                        detected_libraries.append(library)
                        
                except Exception as e:
                    self.logger.warning(f"Error reading properties file {properties_file}: {e}")
                    
        except Exception as e:
            error_msg = f"Error in properties file detection: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        return detected_libraries
    
    def _scan_buildconfig_smali(self, apktool_dir: Path, errors: List[str]) -> List[DetectedLibrary]:
        """Extract library information from BuildConfig.smali files"""
        detected_libraries = []
        
        # Regex patterns for smali field extraction
        re_class = re.compile(r'\.class\s+public\s+final\s+L([^;]+);')
        re_app_id = re.compile(
            r'\.field\s+public\s+static\s+final\s+APPLICATION_ID:Ljava/lang/String;\s*=\s*"([^"]+)"'
        )
        re_lib_pkg = re.compile(
            r'\.field\s+public\s+static\s+final\s+LIBRARY_PACKAGE_NAME:Ljava/lang/String;\s*=\s*"([^"]+)"'
        )
        re_version_name = re.compile(
            r'\.field\s+public\s+static\s+final\s+VERSION_NAME:Ljava/lang/String;\s*=\s*"([^"]*)"'
        )
        re_version_code = re.compile(
            r'\.field\s+public\s+static\s+final\s+VERSION_CODE:I\s*=\s*([+-]?(?:0x[0-9a-fA-F]+|\d+))'
        )
        
        try:
            for buildconfig_file in apktool_dir.rglob("BuildConfig.smali"):
                try:
                    with open(buildconfig_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Extract class path for fallback library name
                    lib_from_class = None
                    m_class = re_class.search(content)
                    if m_class:
                        cls_path = m_class.group(1)
                        if cls_path.endswith("/BuildConfig"):
                            lib_from_class = cls_path.rsplit("/", 1)[0].replace("/", ".")
                    
                    # Priority: APPLICATION_ID -> LIBRARY_PACKAGE_NAME -> class path
                    m_app = re_app_id.search(content)
                    m_pkg = re_lib_pkg.search(content)
                    lib_name = (m_app.group(1) if m_app else 
                               (m_pkg.group(1) if m_pkg else lib_from_class))
                    
                    # Priority: VERSION_NAME -> VERSION_CODE
                    version = None
                    m_vname = re_version_name.search(content)
                    if m_vname:
                        version = m_vname.group(1)
                    else:
                        m_vcode = re_version_code.search(content)
                        if m_vcode:
                            version = self._parse_smali_int(m_vcode.group(1))
                    
                    if lib_name:
                        library = DetectedLibrary(
                            name=lib_name,
                            package_name=lib_name,
                            version=version,
                            detection_method=LibraryDetectionMethod.BUILDCONFIG_ANALYSIS,
                            category=LibraryCategory.UNKNOWN,
                            confidence=0.8,
                            evidence=[f"Found in BuildConfig.smali: {buildconfig_file.name}"],
                            file_paths=[str(buildconfig_file.relative_to(apktool_dir))],
                            source=LibrarySource.SMALI_CLASSES,
                            smali_path=str(buildconfig_file.relative_to(apktool_dir))
                        )
                        # Enhance with version analysis if version is available
                        if version:
                            self._enhance_library_with_version_analysis(library)
                        detected_libraries.append(library)
                        
                except Exception as e:
                    self.logger.warning(f"Error reading BuildConfig file {buildconfig_file}: {e}")
                    
        except Exception as e:
            error_msg = f"Error in BuildConfig detection: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        return detected_libraries
    
    def _parse_smali_int(self, raw: str) -> Optional[str]:
        """Parse smali integer (decimal, hex, negative) and return as string"""
        if not raw:
            return None
        s = raw.strip().lower()
        try:
            if s.startswith('-0x'):
                return str(-int(s[3:], 16))
            if s.startswith('0x'):
                return str(int(s[2:], 16))
            return str(int(s, 10))
        except ValueError:
            return None
    
    def _create_detected_library_from_definition(self, definition: dict, method: LibraryDetectionMethod, 
                                               lib_path: str) -> Optional[DetectedLibrary]:
        """Create DetectedLibrary object from JSONL definition"""
        try:
            lib_id = definition.get("id")
            name = definition.get("name", lib_id)
            lib_type = definition.get("type", "Unknown")
            url = definition.get("url", "")
            
            # Determine category from type
            category = self._map_type_to_category(lib_type)
            
            # Handle license information
            license_val = definition.get("license")
            license_info = None
            if license_val is None:
                license_info = "Unknown"
            elif (isinstance(license_val, str) and license_val.strip() == "") or license_val is False:
                license_info = "No License"
            else:
                license_info = str(license_val)
            
            # Handle anti-features
            anti_features = definition.get("anti", [])
            risk_level = RiskLevel.MEDIUM if anti_features else RiskLevel.LOW
            
            # Create evidence list
            evidence = [f"Found in smali directory: {lib_path}"]
            if anti_features:
                evidence.append(f"Anti-features: {', '.join(anti_features)}")
            if license_info:
                evidence.append(f"License: {license_info}")
            
            return DetectedLibrary(
                name=name,
                package_name=lib_id,
                version=None,  # Version not available in pattern detection
                detection_method=method,
                category=category,
                library_type=LibraryType.THIRD_PARTY,
                confidence=0.95,  # High confidence for pattern matching
                evidence=evidence,
                risk_level=risk_level,
                source=LibrarySource.SMALI_CLASSES,
                url=url,
                license=license_info,
                anti_features=anti_features,
                smali_path=lib_path  # Include the smali path where library was found
            )
            
        except Exception as e:
            self.logger.error(f"Error creating detected library from definition: {e}")
            return None
    
    def _map_type_to_category(self, lib_type: str) -> LibraryCategory:
        """Map library type string to LibraryCategory enum"""
        return self._map_category_string_to_enum(lib_type)
    
    def _map_category_string_to_enum(self, category_str: str) -> LibraryCategory:
        """Map category string to LibraryCategory enum"""
        category_mapping = {
            'ads': LibraryCategory.ADVERTISING,
            'advertising': LibraryCategory.ADVERTISING,
            'analytics': LibraryCategory.ANALYTICS,
            'tracking': LibraryCategory.TRACKING,
            'crash': LibraryCategory.CRASH_REPORTING,
            'social': LibraryCategory.SOCIAL,
            'ui': LibraryCategory.UI_COMPONENT,
            'network': LibraryCategory.NETWORK,
            'networking': LibraryCategory.NETWORK,
            'utility': LibraryCategory.UTILITY,
            'security': LibraryCategory.SECURITY,
            'testing': LibraryCategory.TESTING,
            'development': LibraryCategory.DEVELOPMENT,
            'core': LibraryCategory.UTILITY,
            'authentication': LibraryCategory.SECURITY,
            'location': LibraryCategory.UTILITY,
            'maps': LibraryCategory.UTILITY,
            'media': LibraryCategory.UTILITY,
            'messaging': LibraryCategory.NETWORKING,
            'billing': LibraryCategory.UTILITY,
            'serialization': LibraryCategory.UTILITY,
            'imaging': LibraryCategory.UTILITY,
            'ml': LibraryCategory.UTILITY
        }
        
        category_lower = category_str.lower()
        return category_mapping.get(category_lower, LibraryCategory.UNKNOWN)
    
    def _deduplicate_libraries(self, libraries: List[DetectedLibrary]) -> List[DetectedLibrary]:
        """Remove duplicate libraries based on name and package"""
        seen = {}
        deduplicated = []
        
        for library in libraries:
            # Use name as primary key, package as secondary
            key = (library.name, library.package_name)
            
            if key not in seen:
                seen[key] = library
                deduplicated.append(library)
            else:
                # Keep the one with higher confidence, or merge evidence
                existing = seen[key]
                if library.confidence > existing.confidence:
                    deduplicated.remove(existing)
                    deduplicated.append(library)
                    seen[key] = library
                elif library.confidence == existing.confidence:
                    # Merge evidence from both detections
                    existing.evidence.extend([e for e in library.evidence if e not in existing.evidence])
        
        return deduplicated
    
    def _enhance_library_with_version_analysis(self, library: DetectedLibrary):
        """
        Enhance detected library with version analysis information.
        
        Args:
            library: DetectedLibrary object to enhance with version analysis
        """
        try:
            if not library.version:
                self.logger.debug(f"Version analysis SKIPPED: {library.name} - no version available")
                return
                
            # Debug logging to track what names are being passed
            self.logger.info(f"🔍 VERSION ANALYSIS: Processing {library.name} v{library.version} (package: {library.package_name}, security_enabled: {self.version_analyzer.security_analysis_enabled})")
                
            # Use package_name as primary identifier for version analysis (better for mappings)
            # Fall back to display name if no package_name available
            identifier_name = library.package_name if library.package_name else library.name
            
            # Perform version analysis
            analysis = self.version_analyzer.analyze_library_version(
                identifier_name, library.version, library.package_name
            )
            
            self.logger.info(f"📊 VERSION RESULT: {library.name} -> years_behind={analysis.years_behind}, risk={analysis.security_risk}, recommendation='{analysis.recommendation[:50]}...')")
            
            # Update library with analysis results
            library.years_behind = analysis.years_behind
            library.major_versions_behind = analysis.major_versions_behind
            library.security_risk = analysis.security_risk
            library.version_recommendation = analysis.recommendation
            library.version_analysis_date = analysis.analysis_date.isoformat()
            library.latest_version = analysis.latest_version
            
            # Update risk level based on version analysis
            if analysis.security_risk == "CRITICAL":
                library.risk_level = RiskLevel.CRITICAL
            elif analysis.security_risk == "HIGH":
                library.risk_level = RiskLevel.HIGH
            elif analysis.security_risk == "MEDIUM" and library.risk_level == RiskLevel.LOW:
                library.risk_level = RiskLevel.MEDIUM
                
        except Exception as e:
            self.logger.debug(f"Version analysis failed for {library.name}: {e}")
    
    def _print_version_analysis_results(self, libraries: List[DetectedLibrary]):
        """
        Print enhanced version analysis results to console.
        
        Format: library name (version): smali path : years behind
        Example: Gson (2.8.5): /com/google/gson/ : 2.1 years behind
        """
        libraries_with_versions = [lib for lib in libraries if lib.version]
        
        if not libraries_with_versions:
            self.logger.info("No libraries with version information found for version analysis display")
            return
        
        self.logger.info(f"Found {len(libraries_with_versions)} libraries with version information for analysis")
            
        print("\n" + "="*80)
        print("📚 LIBRARY VERSION ANALYSIS")
        print("="*80)
        
        # Group libraries by security risk and also include libraries without risk assessment
        critical_libs = [lib for lib in libraries_with_versions if lib.security_risk == "CRITICAL"]
        high_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk == "HIGH"]
        medium_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk == "MEDIUM"]
        low_risk_libs = [lib for lib in libraries_with_versions if lib.security_risk in ["LOW", None]]
        
        # Also show ALL libraries with versions, even if version analysis failed
        all_versioned_libs = libraries_with_versions
        
        self.logger.info(f"Version analysis grouping: Critical={len(critical_libs)}, High={len(high_risk_libs)}, Medium={len(medium_risk_libs)}, Low={len(low_risk_libs)}, Total={len(all_versioned_libs)}")
        
        # Print critical libraries first
        if critical_libs:
            print(f"\n⚠️  CRITICAL RISK LIBRARIES ({len(critical_libs)}):")
            print("-" * 40)
            for lib in sorted(critical_libs, key=lambda x: x.years_behind or 0, reverse=True):
                print(f"   {lib.format_version_output()}")
                if lib.version_recommendation:
                    print(f"   └─ {lib.version_recommendation}")
        
        # Print high risk libraries
        if high_risk_libs:
            print(f"\n⚠️  HIGH RISK LIBRARIES ({len(high_risk_libs)}):")
            print("-" * 40)
            for lib in sorted(high_risk_libs, key=lambda x: x.years_behind or 0, reverse=True):
                print(f"   {lib.format_version_output()}")
                if lib.version_recommendation:
                    print(f"   └─ {lib.version_recommendation}")
        
        # Print medium risk libraries
        if medium_risk_libs:
            print(f"\n⚠️  MEDIUM RISK LIBRARIES ({len(medium_risk_libs)}):")
            print("-" * 40)
            for lib in sorted(medium_risk_libs, key=lambda x: x.years_behind or 0, reverse=True):
                print(f"   {lib.format_version_output()}")
        
        # Print low risk libraries (summary only)
        if low_risk_libs:
            current_libs = [lib for lib in low_risk_libs if (lib.years_behind or 0) < 0.5]
            outdated_libs = [lib for lib in low_risk_libs if (lib.years_behind or 0) >= 0.5]
            
            if outdated_libs:
                print(f"\n📋 OUTDATED LIBRARIES ({len(outdated_libs)}):")
                print("-" * 40)
                for lib in sorted(outdated_libs, key=lambda x: x.years_behind or 0, reverse=True):
                    print(f"   {lib.format_version_output()}")
            
            if current_libs:
                print(f"\n✅ CURRENT LIBRARIES ({len(current_libs)}):")
                print("-" * 40)
                for lib in sorted(current_libs, key=lambda x: x.name):
                    print(f"   {lib.format_version_output()}")
        
        # ALWAYS show all libraries with versions, even if risk analysis failed
        if all_versioned_libs and not (critical_libs or high_risk_libs or medium_risk_libs):
            print(f"\n📚 ALL LIBRARIES WITH VERSION INFO ({len(all_versioned_libs)}):")
            print("-" * 60)
            for lib in sorted(all_versioned_libs, key=lambda x: x.name.lower()):
                formatted = lib.format_version_output()
                print(f"   {formatted}")
                
                # Show additional info if available
                if hasattr(lib, 'latest_version') and lib.latest_version and lib.latest_version != lib.version:
                    print(f"   └─ Latest available: {lib.latest_version}")
                if lib.version_recommendation and "Unable to determine" not in lib.version_recommendation:
                    print(f"   └─ {lib.version_recommendation}")
        
        # Print summary statistics
        total_libs = len(libraries_with_versions)
        if total_libs > 0:
            print("\n📊 SUMMARY:")
            print("-" * 40)
            print(f"   Total libraries analyzed: {total_libs}")
            print(f"   Critical risk: {len(critical_libs)}")
            print(f"   High risk: {len(high_risk_libs)}")  
            print(f"   Medium risk: {len(medium_risk_libs)}")
            print(f"   Low risk: {len(low_risk_libs)}")
            
            libs_with_years = [lib for lib in libraries_with_versions if lib.years_behind is not None]
            if libs_with_years:
                avg_years = sum(lib.years_behind for lib in libs_with_years) / len(libs_with_years)
                print(f"   Average years behind: {avg_years:.1f}")
            else:
                print("   Years behind analysis: Not available (API timeouts/errors)")
        
        print("="*80)