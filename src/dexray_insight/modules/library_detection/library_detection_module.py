#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Module - Refactored Main Module

Third-party library detection module using multi-stage analysis with specialized engines.
Refactored to use submodules following Single Responsibility Principle.

Phase 6.5 TDD Refactoring: Main module now delegates to specialized engines
and imports patterns/signatures from dedicated submodules.
"""

import logging
import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass

from dexray_insight.core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, register_module
from dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryDetectionMethod, LibraryCategory, 
    LibraryType, LibrarySource
)

# Import from submodules
from .patterns import LIBRARY_PATTERNS
from .engines import LibraryDetectionCoordinator
from .signatures import ClassSignatureExtractor, SignatureMatcher


@dataclass
class LibraryDetectionResult(BaseResult):
    """Result class for library detection analysis"""
    detected_libraries: List[DetectedLibrary] = None
    total_libraries: int = 0
    heuristic_libraries: List[DetectedLibrary] = None
    similarity_libraries: List[DetectedLibrary] = None
    analysis_errors: List[str] = None
    stage1_time: float = 0.0
    stage2_time: float = 0.0
    
    def __post_init__(self):
        if self.detected_libraries is None:
            self.detected_libraries = []
        if self.heuristic_libraries is None:
            self.heuristic_libraries = []
        if self.similarity_libraries is None:
            self.similarity_libraries = []
        if self.analysis_errors is None:
            self.analysis_errors = []
        self.total_libraries = len(self.detected_libraries)
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'detected_libraries': [lib.to_dict() for lib in self.detected_libraries],
            'total_libraries': self.total_libraries,
            'heuristic_libraries': [lib.to_dict() for lib in self.heuristic_libraries],
            'similarity_libraries': [lib.to_dict() for lib in self.similarity_libraries],
            'analysis_errors': self.analysis_errors,
            'stage1_time': self.stage1_time,
            'stage2_time': self.stage2_time
        })
        return base_dict


@register_module('library_detection')
class LibraryDetectionModule(BaseAnalysisModule):
    """
    Third-party library detection module using multi-stage analysis.
    
    Phase 6.5 TDD Refactoring: Refactored to use specialized engines and
    patterns/signatures from dedicated submodules following SRP.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Configuration options
        self.enable_stage1 = config.get('enable_heuristic', True)
        self.enable_stage2 = config.get('enable_similarity', True)
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        self.similarity_threshold = config.get('similarity_threshold', 0.85)
        self.class_similarity_threshold = config.get('class_similarity_threshold', 0.7)
        
        # Import library patterns from patterns submodule
        self.LIBRARY_PATTERNS = LIBRARY_PATTERNS.copy()
        
        # Custom library patterns from config
        self.custom_patterns = config.get('custom_patterns', {})
        if self.custom_patterns:
            self.LIBRARY_PATTERNS.update(self.custom_patterns)
            
        # Initialize specialized signature components
        self.signature_extractor = ClassSignatureExtractor()
        self.signature_matcher = SignatureMatcher(self.similarity_threshold)
            
        # Phase 6 TDD Refactoring: Initialize detection coordinator
        self.detection_coordinator = LibraryDetectionCoordinator(self)
    
    def get_dependencies(self) -> List[str]:
        """Dependencies: string analysis for class names, manifest analysis for permissions/services"""
        return ['string_analysis', 'manifest_analysis']
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> LibraryDetectionResult:
        """
        Perform comprehensive library detection analysis using specialized detection engines.
        
        Refactored coordinator function that delegates to specialized detection engines
        following the Single Responsibility Principle. Each detection concern is handled
        by a dedicated engine with its own timing and error management.
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            LibraryDetectionResult with comprehensive detection results
        """
        # Phase 6.5 TDD Refactoring: Delegate to specialized coordinator from engines submodule
        return self.detection_coordinator.execute_full_analysis(apk_path, context)
    
    # Legacy detection methods - kept for backward compatibility
    # These will be called by the engines
    
    def _perform_heuristic_detection(self, context: AnalysisContext, errors: List[str]) -> List[DetectedLibrary]:
        """
        Stage 1: Heuristic-based library detection using known patterns
        
        Args:
            context: Analysis context with existing results
            errors: List to append any analysis errors
            
        Returns:
            List of detected libraries using heuristic methods
        """
        detected_libraries = []
        
        try:
            # Get existing analysis results
            string_results = context.get_result('string_analysis')
            manifest_results = context.get_result('manifest_analysis')
            
            if not string_results:
                errors.append("String analysis results not available for heuristic detection")
                return detected_libraries
            
            # Extract all strings for pattern matching
            all_strings = getattr(string_results, 'all_strings', [])
            if not all_strings:
                self.logger.warning("No strings available from string analysis")
                all_strings = []
            
            # Extract package names from class names
            package_names = self._extract_package_names(all_strings)
            class_names = self._extract_class_names(all_strings)
            
            self.logger.debug(f"Found {len(package_names)} unique package names and {len(class_names)} class names")
            
            # Check each known library pattern
            for lib_name, pattern in self.LIBRARY_PATTERNS.items():
                library = self._check_library_pattern(lib_name, pattern, package_names, class_names, manifest_results)
                if library:
                    detected_libraries.append(library)
                    self.logger.debug(f"Detected {lib_name} via heuristic analysis")
            
        except Exception as e:
            error_msg = f"Error in heuristic detection: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        return detected_libraries
    
    def _perform_similarity_detection(self, context: AnalysisContext, errors: List[str], 
                                    existing_libraries: List[DetectedLibrary]) -> List[DetectedLibrary]:
        """
        Stage 2: Similarity-based detection using LibScan-inspired approach
        """
        detected_libraries = []
        
        try:
            if not context.androguard_obj:
                self.logger.warning("Androguard object not available for similarity detection")
                return detected_libraries
            
            # Get DEX object for class analysis
            dex_objects = context.androguard_obj.get_androguard_dex()
            if not dex_objects:
                self.logger.warning("No DEX objects available for similarity analysis")
                return detected_libraries
            
            self.logger.debug("Building class dependency graph and extracting signatures...")
            
            # Extract comprehensive class features using signature extractor
            _ = self.signature_extractor.build_class_dependency_graph(dex_objects)
            _ = self.signature_extractor.extract_method_opcode_patterns(dex_objects)
            _ = self.signature_extractor.extract_call_chain_patterns(dex_objects)
            
            # Perform LibScan-style similarity matching using signature matcher
            class_signatures = self.signature_extractor.extract_class_signatures(dex_objects)
            similarity_libraries = self.signature_matcher.match_class_signatures(
                class_signatures, existing_libraries
            )
            
            detected_libraries.extend(similarity_libraries)
            
            self.logger.debug(f"Similarity detection found {len(similarity_libraries)} additional libraries")
            
        except Exception as e:
            error_msg = f"Error in similarity detection: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        return detected_libraries
    
    def _extract_package_names(self, strings: List[str]) -> Set[str]:
        """Extract package names from string data"""
        package_names = set()
        
        # Pattern for Java package names (at least 2 segments with dots)
        package_pattern = re.compile(r'^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$')
        
        for string in strings:
            if isinstance(string, str) and package_pattern.match(string):
                # Exclude very common Android packages to reduce noise
                if not string.startswith(('android.', 'java.', 'javax.', 'org.w3c.', 'org.xml.')):
                    package_names.add(string)
        
        return package_names
    
    def _extract_class_names(self, strings: List[str]) -> Set[str]:
        """Extract class names from string data"""
        class_names = set()
        
        # Pattern for class names (CamelCase, possibly with package prefix)
        class_pattern = re.compile(r'(?:^|\.)[A-Z][a-zA-Z0-9]*(?:\$[A-Z][a-zA-Z0-9]*)*$')
        
        for string in strings:
            if isinstance(string, str) and class_pattern.search(string):
                # Extract just the class name part
                parts = string.split('.')
                for part in parts:
                    if re.match(r'^[A-Z][a-zA-Z0-9]*', part):
                        class_names.add(part.split('$')[0])  # Remove inner class suffix
        
        return class_names
    
    def _check_library_pattern(self, lib_name: str, pattern: Dict[str, Any], 
                              package_names: Set[str], class_names: Set[str], 
                              manifest_results: Any) -> Optional[DetectedLibrary]:
        """Check if a library pattern matches the detected packages and classes"""
        # This method contains the original pattern matching logic
        # Keeping it here for backward compatibility with existing detection logic
        
        matches = []
        confidence = 0.0
        
        # Check package matches
        required_packages = pattern.get('packages', [])
        package_matches = 0
        for package in required_packages:
            for detected_package in package_names:
                if package in detected_package or detected_package.startswith(package):
                    matches.append(f"Package: {package}")
                    package_matches += 1
                    break
        
        # Check class matches  
        required_classes = pattern.get('classes', [])
        class_matches = 0
        for class_name in required_classes:
            if class_name in class_names:
                matches.append(f"Class: {class_name}")
                class_matches += 1
        
        # Check permission matches
        if manifest_results and hasattr(manifest_results, 'permissions'):
            required_permissions = pattern.get('permissions', [])
            permission_matches = 0
            for permission in required_permissions:
                if permission in manifest_results.permissions:
                    matches.append(f"Permission: {permission}")
                    permission_matches += 1
        
        # Calculate confidence based on matches
        total_criteria = len(required_packages) + len(required_classes) + len(pattern.get('permissions', []))
        if total_criteria > 0:
            confidence = len(matches) / total_criteria
        
        # Require minimum confidence threshold
        if confidence >= self.confidence_threshold:
            return DetectedLibrary(
                name=lib_name,
                detection_method=LibraryDetectionMethod.HEURISTIC,
                category=pattern.get('category', LibraryCategory.UNKNOWN),
                confidence=confidence,
                evidence=matches
            )
        
        return None
    
    def _detect_native_libraries(self, context: AnalysisContext) -> List[DetectedLibrary]:
        """Detect native (.so) libraries from lib/ directories"""
        native_libraries = []
        
        try:
            if not context.androguard_obj:
                return native_libraries
                
            apk = context.androguard_obj.get_androguard_apk()
            if not apk:
                return native_libraries
            
            # Get all files in the APK
            files = apk.get_files()
            lib_files = [f for f in files if f.startswith('lib/') and f.endswith('.so')]
            
            # Group by library name and collect architectures
            lib_groups = {}
            for lib_file in lib_files:
                parts = lib_file.split('/')
                if len(parts) >= 3:
                    arch = parts[1]  # e.g., 'arm64-v8a'
                    lib_name = parts[-1]  # e.g., 'libffmpeg.so'
                    
                    if lib_name not in lib_groups:
                        lib_groups[lib_name] = {
                            'architectures': [],
                            'paths': [],
                            'size': 0
                        }
                    
                    lib_groups[lib_name]['architectures'].append(arch)
                    lib_groups[lib_name]['paths'].append(lib_file)
                    
                    # Try to get file size
                    try:
                        lib_data = apk.get_file(lib_file)
                        if lib_data:
                            lib_groups[lib_name]['size'] += len(lib_data)
                    except Exception:
                        pass
            
            # Create DetectedLibrary objects for each native library
            for lib_name, lib_info in lib_groups.items():
                detected_library = DetectedLibrary(
                    name=lib_name,
                    detection_method=LibraryDetectionMethod.NATIVE,
                    category=LibraryCategory.UTILITY,  # Default for native libs
                    confidence=1.0,  # High confidence for native detection
                    evidence=[f"Found in {len(lib_info['paths'])} architecture(s)"],
                    architectures=lib_info['architectures'],
                    file_paths=lib_info['paths'],
                    size_bytes=lib_info['size'],
                    source=LibrarySource.NATIVE_LIBS
                )
                native_libraries.append(detected_library)
                
        except Exception as e:
            self.logger.error(f"Error detecting native libraries: {str(e)}")
        
        return native_libraries
    
    def _detect_androidx_libraries(self, context: AnalysisContext) -> List[DetectedLibrary]:
        """Detect AndroidX libraries from package analysis"""
        androidx_libraries = []
        
        try:
            # Get existing analysis results
            string_results = context.get_result('string_analysis')
            if not string_results:
                return androidx_libraries
            
            all_strings = getattr(string_results, 'all_strings', [])
            
            # Look for AndroidX packages
            androidx_packages = set()
            for string in all_strings:
                if isinstance(string, str) and string.startswith('androidx.'):
                    # Extract main AndroidX component
                    parts = string.split('.')
                    if len(parts) >= 2:
                        component = f"androidx.{parts[1]}"
                        androidx_packages.add(component)
            
            # Map AndroidX packages to library names
            androidx_mapping = {
                'androidx.appcompat': 'AndroidX AppCompat',
                'androidx.core': 'AndroidX Core',
                'androidx.lifecycle': 'AndroidX Lifecycle',
                'androidx.room': 'AndroidX Room',
                'androidx.work': 'AndroidX WorkManager',
                'androidx.recyclerview': 'AndroidX RecyclerView',
                'androidx.fragment': 'AndroidX Fragments',
                'androidx.navigation': 'AndroidX Navigation',
                'androidx.databinding': 'AndroidX Data Binding',
                'androidx.constraintlayout': 'AndroidX ConstraintLayout'
            }
            
            # Create detected libraries for each AndroidX component
            for package, lib_name in androidx_mapping.items():
                if package in androidx_packages:
                    detected_library = DetectedLibrary(
                        name=lib_name,
                        package_name=package,
                        detection_method=LibraryDetectionMethod.HEURISTIC,
                        category=LibraryCategory.ANDROIDX,
                        library_type=LibraryType.ANDROIDX,
                        confidence=0.9,
                        evidence=[f"Package: {package}"],
                        source=LibrarySource.SMALI_CLASSES
                    )
                    androidx_libraries.append(detected_library)
                    
        except Exception as e:
            self.logger.error(f"Error detecting AndroidX libraries: {str(e)}")
        
        return androidx_libraries
    
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
                # Keep the one with higher confidence
                existing = seen[key]
                if library.confidence > existing.confidence:
                    deduplicated.remove(existing)
                    deduplicated.append(library)
                    seen[key] = library
        
        return deduplicated
    
    def _validate_config(self) -> bool:
        """Validate module configuration"""
        if not isinstance(self.confidence_threshold, (int, float)) or not (0 <= self.confidence_threshold <= 1):
            self.logger.error("confidence_threshold must be a number between 0 and 1")
            return False
        
        if not isinstance(self.similarity_threshold, (int, float)) or not (0 <= self.similarity_threshold <= 1):
            self.logger.error("similarity_threshold must be a number between 0 and 1")
            return False
        
        return True