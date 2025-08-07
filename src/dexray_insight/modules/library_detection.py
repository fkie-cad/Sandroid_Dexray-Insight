#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module
from ..results.LibraryDetectionResults import (
    DetectedLibrary, LibraryDetectionMethod, LibraryCategory, 
    LibraryType, RiskLevel, LibrarySource
)

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
    """Third-party library detection module using two-stage analysis"""
    
    # Known library patterns for heuristic detection
    LIBRARY_PATTERNS = {
        # Analytics Libraries
        'Google Analytics': {
            'packages': ['com.google.analytics', 'com.google.android.gms.analytics'],
            'category': LibraryCategory.ANALYTICS,
            'classes': ['GoogleAnalytics', 'Tracker', 'Analytics'],
            'permissions': ['android.permission.ACCESS_NETWORK_STATE', 'android.permission.INTERNET']
        },
        'Firebase Analytics': {
            'packages': ['com.google.firebase.analytics', 'com.google.firebase'],
            'category': LibraryCategory.ANALYTICS,
            'classes': ['FirebaseAnalytics', 'FirebaseApp'],
            'manifest_keys': ['com.google.firebase.analytics.connector.internal.APPLICATION_ID']
        },
        'Flurry Analytics': {
            'packages': ['com.flurry.android'],
            'category': LibraryCategory.ANALYTICS,
            'classes': ['FlurryAgent', 'FlurryAnalytics']
        },
        'Mixpanel': {
            'packages': ['com.mixpanel.android'],
            'category': LibraryCategory.ANALYTICS,
            'classes': ['MixpanelAPI', 'Mixpanel']
        },
        
        # Advertising Libraries
        'AdMob': {
            'packages': ['com.google.android.gms.ads', 'com.google.ads'],
            'category': LibraryCategory.ADVERTISING,
            'classes': ['AdView', 'InterstitialAd', 'AdRequest'],
            'permissions': ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE']
        },
        'Facebook Audience Network': {
            'packages': ['com.facebook.ads'],
            'category': LibraryCategory.ADVERTISING,
            'classes': ['AdView', 'InterstitialAd', 'NativeAd']
        },
        'Unity Ads': {
            'packages': ['com.unity3d.ads'],
            'category': LibraryCategory.ADVERTISING,
            'classes': ['UnityAds', 'UnityBannerSize']
        },
        
        # Crash Reporting
        'Crashlytics': {
            'packages': ['com.crashlytics.android', 'io.fabric.sdk.android.services.crashlytics'],
            'category': LibraryCategory.CRASH_REPORTING,
            'classes': ['Crashlytics', 'CrashlyticsCore']
        },
        'Bugsnag': {
            'packages': ['com.bugsnag.android'],
            'category': LibraryCategory.CRASH_REPORTING,
            'classes': ['Bugsnag', 'Client']
        },
        'Sentry': {
            'packages': ['io.sentry'],
            'category': LibraryCategory.CRASH_REPORTING,
            'classes': ['Sentry', 'SentryClient']
        },
        
        # Social Media
        'Facebook SDK': {
            'packages': ['com.facebook', 'com.facebook.android'],
            'category': LibraryCategory.SOCIAL_MEDIA,
            'classes': ['FacebookSdk', 'LoginManager', 'GraphRequest'],
            'permissions': ['android.permission.INTERNET']
        },
        'Twitter SDK': {
            'packages': ['com.twitter.sdk.android'],
            'category': LibraryCategory.SOCIAL_MEDIA,
            'classes': ['Twitter', 'TwitterCore']
        },
        
        # Networking
        'OkHttp': {
            'packages': ['okhttp3', 'com.squareup.okhttp3'],
            'category': LibraryCategory.NETWORKING,
            'classes': ['OkHttpClient', 'Request', 'Response']
        },
        'Retrofit': {
            'packages': ['retrofit2', 'com.squareup.retrofit2'],
            'category': LibraryCategory.NETWORKING,
            'classes': ['Retrofit', 'Call', 'Response']
        },
        'Volley': {
            'packages': ['com.android.volley'],
            'category': LibraryCategory.NETWORKING,
            'classes': ['RequestQueue', 'Request', 'Response']
        },
        
        # UI Frameworks
        'Butterknife': {
            'packages': ['butterknife'],
            'category': LibraryCategory.UI_FRAMEWORK,
            'classes': ['ButterKnife', 'Bind', 'OnClick']
        },
        'Material Design': {
            'packages': ['com.google.android.material'],
            'category': LibraryCategory.UI_FRAMEWORK,
            'classes': ['MaterialButton', 'MaterialCardView']
        },
        
        # Image Loading
        'Glide': {
            'packages': ['com.bumptech.glide'],
            'category': LibraryCategory.MEDIA,
            'classes': ['Glide', 'RequestManager']
        },
        'Picasso': {
            'packages': ['com.squareup.picasso'],
            'category': LibraryCategory.MEDIA,
            'classes': ['Picasso', 'RequestCreator']
        },
        'Fresco': {
            'packages': ['com.facebook.fresco'],
            'category': LibraryCategory.MEDIA,
            'classes': ['Fresco', 'SimpleDraweeView']
        },
        
        # Payment
        'Stripe': {
            'packages': ['com.stripe.android'],
            'category': LibraryCategory.PAYMENT,
            'classes': ['Stripe', 'PaymentConfiguration']
        },
        'PayPal': {
            'packages': ['com.paypal.android'],
            'category': LibraryCategory.PAYMENT,
            'classes': ['PayPalConfiguration', 'PayPalPayment']
        },
        
        # Database
        'Room': {
            'packages': ['androidx.room', 'android.arch.persistence.room'],
            'category': LibraryCategory.DATABASE,
            'classes': ['Room', 'RoomDatabase', 'Entity']
        },
        'Realm': {
            'packages': ['io.realm'],
            'category': LibraryCategory.DATABASE,
            'classes': ['Realm', 'RealmObject', 'RealmConfiguration']
        },
        
        # Security
        'SQLCipher': {
            'packages': ['net.sqlcipher'],
            'category': LibraryCategory.SECURITY,
            'classes': ['SQLiteDatabase', 'SQLiteOpenHelper']
        },
        
        # Testing
        'Mockito': {
            'packages': ['org.mockito'],
            'category': LibraryCategory.TESTING,
            'classes': ['Mockito', 'Mock', 'Spy']
        },
        'Espresso': {
            'packages': ['androidx.test.espresso'],
            'category': LibraryCategory.TESTING,
            'classes': ['Espresso', 'ViewInteraction']
        },
        
        # Utilities
        'Gson': {
            'packages': ['com.google.gson'],
            'category': LibraryCategory.UTILITY,
            'classes': ['Gson', 'GsonBuilder', 'JsonParser']
        },
        'Jackson': {
            'packages': ['com.fasterxml.jackson'],
            'category': LibraryCategory.UTILITY,
            'classes': ['ObjectMapper', 'JsonNode']
        },
        'Apache Commons': {
            'packages': ['org.apache.commons'],
            'category': LibraryCategory.UTILITY,
            'classes': ['StringUtils', 'CollectionUtils', 'FileUtils']
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Configuration options
        self.enable_stage1 = config.get('enable_heuristic', True)
        self.enable_stage2 = config.get('enable_similarity', True)
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        self.similarity_threshold = config.get('similarity_threshold', 0.85)
        self.class_similarity_threshold = config.get('class_similarity_threshold', 0.7)
        
        # Custom library patterns from config
        self.custom_patterns = config.get('custom_patterns', {})
        if self.custom_patterns:
            self.LIBRARY_PATTERNS.update(self.custom_patterns)
    
    def get_dependencies(self) -> List[str]:
        """Dependencies: string analysis for class names, manifest analysis for permissions/services"""
        return ['string_analysis', 'manifest_analysis']
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> LibraryDetectionResult:
        """
        Perform two-stage library detection analysis
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            LibraryDetectionResult with detection results
        """
        start_time = time.time()
        
        self.logger.info(f"Starting two-stage library detection for {apk_path}")
        
        try:
            detected_libraries = []
            stage1_libraries = []
            stage2_libraries = []
            analysis_errors = []
            
            # Stage 1: Heuristic Detection
            stage1_start = time.time()
            if self.enable_stage1:
                self.logger.debug("Starting Stage 1: Heuristic-based detection")
                stage1_libraries = self._perform_heuristic_detection(context, analysis_errors)
                detected_libraries.extend(stage1_libraries)
                self.logger.info(f"Stage 1 detected {len(stage1_libraries)} libraries using heuristics")
            stage1_time = time.time() - stage1_start
            
            # Stage 2: Similarity-based Detection (LibScan-style)
            stage2_start = time.time()
            if self.enable_stage2:
                self.logger.debug("Starting Stage 2: Similarity-based detection")
                stage2_libraries = self._perform_similarity_detection(context, analysis_errors, detected_libraries)
                detected_libraries.extend(stage2_libraries)
                self.logger.info(f"Stage 2 detected {len(stage2_libraries)} additional libraries using similarity analysis")
            stage2_time = time.time() - stage2_start
            
            # Stage 3: Native Library Detection
            stage3_start = time.time()
            self.logger.debug("Starting Stage 3: Native library detection")
            try:
                native_libraries = self._detect_native_libraries(context)
                detected_libraries.extend(native_libraries)
                self.logger.info(f"Stage 3 detected {len(native_libraries)} native libraries")
            except Exception as e:
                error_msg = f"Native library detection failed: {str(e)}"
                analysis_errors.append(error_msg)
                self.logger.debug(error_msg)
            stage3_time = time.time() - stage3_start
            
            # Stage 4: AndroidX Library Detection
            stage4_start = time.time()
            self.logger.debug("Starting Stage 4: AndroidX library detection")
            try:
                androidx_libraries = self._detect_androidx_libraries(context)
                detected_libraries.extend(androidx_libraries)
                self.logger.info(f"Stage 4 detected {len(androidx_libraries)} AndroidX libraries")
            except Exception as e:
                error_msg = f"AndroidX library detection failed: {str(e)}"
                analysis_errors.append(error_msg)
                self.logger.debug(error_msg)
            stage4_time = time.time() - stage4_start
            
            # Remove duplicates based on name and package
            detected_libraries = self._deduplicate_libraries(detected_libraries)
            
            execution_time = time.time() - start_time
            
            self.logger.info(f"Library detection completed: {len(detected_libraries)} unique libraries detected")
            self.logger.info(f"Total execution time: {execution_time:.2f}s (Stage 1: {stage1_time:.2f}s, Stage 2: {stage2_time:.2f}s, Stage 3: {stage3_time:.2f}s, Stage 4: {stage4_time:.2f}s)")
            
            return LibraryDetectionResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                detected_libraries=detected_libraries,
                heuristic_libraries=stage1_libraries,
                similarity_libraries=stage2_libraries,
                analysis_errors=analysis_errors,
                stage1_time=stage1_time,
                stage2_time=stage2_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Library detection analysis failed: {str(e)}"
            self.logger.error(error_msg)
            
            return LibraryDetectionResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=error_msg,
                analysis_errors=[error_msg]
            )
    
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
        
        This implements a sophisticated similarity detection system inspired by LibScan that uses:
        1. Method-opcode similarity analysis
        2. Call-chain-opcode relationship analysis  
        3. Class dependency graph construction
        4. Structural similarity matching
        
        Args:
            context: Analysis context
            errors: List to append any analysis errors
            existing_libraries: Already detected libraries to avoid duplicates
            
        Returns:
            List of detected libraries using similarity analysis
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
            
            # Extract comprehensive class features for similarity analysis
            class_features = self._build_class_dependency_graph(dex_objects)
            
            # Extract method-opcode patterns
            method_patterns = self._extract_method_opcode_patterns(dex_objects)
            
            # Extract call-chain relationships
            call_chains = self._extract_call_chain_patterns(dex_objects)
            
            # Perform LibScan-style similarity matching
            similarity_libraries = self._perform_libscan_matching(
                class_features, method_patterns, call_chains, existing_libraries
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
        """
        Check if a library pattern matches the detected packages and classes
        
        Args:
            lib_name: Name of the library to check
            pattern: Library pattern definition
            package_names: Set of detected package names
            class_names: Set of detected class names
            manifest_results: Manifest analysis results
            
        Returns:
            DetectedLibrary if pattern matches, None otherwise
        """
        evidence = []
        confidence = 0.0
        matched_packages = []
        matched_classes = []
        
        # Check package patterns
        if 'packages' in pattern:
            for pkg_pattern in pattern['packages']:
                for pkg_name in package_names:
                    if pkg_name.startswith(pkg_pattern):
                        matched_packages.append(pkg_name)
                        evidence.append(f"Package: {pkg_name}")
                        confidence += 0.4  # High weight for package matches
        
        # Check class patterns
        if 'classes' in pattern:
            for class_pattern in pattern['classes']:
                if class_pattern in class_names:
                    matched_classes.append(class_pattern)
                    evidence.append(f"Class: {class_pattern}")
                    confidence += 0.3  # Medium weight for class matches
        
        # Check manifest elements (permissions, services, etc.)
        if manifest_results and 'permissions' in pattern:
            manifest_perms = getattr(manifest_results, 'permissions', [])
            for permission in pattern['permissions']:
                if permission in manifest_perms:
                    evidence.append(f"Permission: {permission}")
                    confidence += 0.2  # Lower weight for permission matches
        
        # Check manifest metadata
        if manifest_results and 'manifest_keys' in pattern:
            # This would need to be expanded based on manifest analysis structure
            for key in pattern['manifest_keys']:
                evidence.append(f"Manifest key: {key}")
                confidence += 0.3
        
        # Only consider it a detection if confidence meets threshold
        if confidence >= self.confidence_threshold and evidence:
            # Normalize confidence to [0, 1] range
            normalized_confidence = min(confidence, 1.0)
            
            # Determine primary package name
            primary_package = matched_packages[0] if matched_packages else None
            
            return DetectedLibrary(
                name=lib_name,
                package_name=primary_package,
                category=pattern.get('category', LibraryCategory.UNKNOWN),
                confidence=normalized_confidence,
                detection_method=LibraryDetectionMethod.HEURISTIC,
                evidence=evidence,
                classes_detected=matched_classes
            )
        
        return None
    
    def _extract_class_signatures(self, dex_objects: List[Any]) -> Dict[str, Any]:
        """
        Extract class signatures for similarity analysis
        
        Args:
            dex_objects: List of DEX objects from androguard
            
        Returns:
            Dictionary of class signatures
        """
        signatures = {}
        
        try:
            for dex in dex_objects:
                # Get all classes from DEX
                for cls in dex.get_classes():
                    class_name = cls.get_name()
                    
                    # Skip Android framework classes
                    if class_name.startswith('Landroid/') or class_name.startswith('Ljava/'):
                        continue
                    
                    # Extract method signatures and opcodes
                    method_signatures = []
                    for method in cls.get_methods():
                        opcodes = []
                        try:
                            # Get method bytecode
                            if method.get_code():
                                for instruction in method.get_code().get_bc().get_instructions():
                                    opcodes.append(instruction.get_name())
                        except Exception:
                            pass
                        
                        method_signatures.append({
                            'name': method.get_name(),
                            'descriptor': method.get_descriptor(),
                            'opcodes': opcodes
                        })
                    
                    signatures[class_name] = {
                        'methods': method_signatures,
                        'superclass': cls.get_superclassname(),
                        'interfaces': cls.get_interfaces()
                    }
                    
        except Exception as e:
            self.logger.error(f"Error extracting class signatures: {str(e)}")
        
        return signatures
    
    def _match_class_signatures(self, signatures: Dict[str, Any], 
                               existing_libraries: List[DetectedLibrary]) -> List[DetectedLibrary]:
        """
        Match class signatures against known library patterns
        
        This is a simplified implementation. A full LibScan approach would
        require a comprehensive database of library signatures.
        
        Args:
            signatures: Extracted class signatures
            existing_libraries: Already detected libraries
            
        Returns:
            List of libraries detected via similarity
        """
        detected_libraries = []
        existing_names = {lib.name for lib in existing_libraries}
        
        # Simplified similarity detection based on method patterns
        # This would be much more sophisticated in a full implementation
        
        try:
            # Look for specific method patterns that indicate library usage
            library_indicators = {
                'Dagger': ['inject', 'provides', 'component'],
                'RxJava': ['subscribe', 'observable', 'scheduler'],
                'Timber': ['plant', 'tree', 'log'],
                'LeakCanary': ['install', 'watchActivity', 'heap'],
                'EventBus': ['register', 'unregister', 'post', 'subscribe']
            }
            
            for lib_name, method_patterns in library_indicators.items():
                if lib_name in existing_names:
                    continue
                
                matches = 0
                evidence = []
                
                for class_name, class_sig in signatures.items():
                    for method in class_sig.get('methods', []):
                        method_name = method.get('name', '').lower()
                        for pattern in method_patterns:
                            if pattern in method_name:
                                matches += 1
                                evidence.append(f"Method pattern: {method_name}")
                
                # If we found enough matches, consider it a detection
                if matches >= 2:  # Threshold for similarity detection
                    confidence = min(matches * 0.15, 0.95)  # Scale confidence
                    
                    detected_libraries.append(DetectedLibrary(
                        name=lib_name,
                        confidence=confidence,
                        detection_method=LibraryDetectionMethod.SIMILARITY,
                        evidence=evidence[:5],  # Limit evidence list
                        similarity_score=confidence
                    ))
            
        except Exception as e:
            self.logger.error(f"Error in signature matching: {str(e)}")
        
        return detected_libraries
    
    def _deduplicate_libraries(self, libraries: List[DetectedLibrary]) -> List[DetectedLibrary]:
        """
        Remove duplicate library detections based on name and package
        
        Args:
            libraries: List of detected libraries
            
        Returns:
            Deduplicated list of libraries
        """
        seen = set()
        deduplicated = []
        
        for library in libraries:
            # Create a unique key based on name and package
            key = (library.name.lower(), library.package_name)
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(library)
            else:
                # If we see a duplicate, prefer the one with higher confidence
                for i, existing in enumerate(deduplicated):
                    if (existing.name.lower() == library.name.lower() and 
                        existing.package_name == library.package_name):
                        if library.confidence > existing.confidence:
                            # Replace with higher confidence detection
                            deduplicated[i] = library
                        break
        
        return deduplicated
    
    def _build_class_dependency_graph(self, dex_objects: List[Any]) -> Dict[str, Dict[str, Any]]:
        """
        Build class dependency graph (CDG) for structural similarity analysis
        
        Args:
            dex_objects: List of DEX objects from androguard
            
        Returns:
            Dictionary mapping class names to their dependency information
        """
        class_graph = {}
        
        try:
            for dex in dex_objects:
                for cls in dex.get_classes():
                    class_name = cls.get_name()
                    
                    # Skip Android framework classes
                    if self._is_framework_class(class_name):
                        continue
                    
                    # Extract class features
                    class_info = {
                        'name': class_name,
                        'modifiers': self._get_class_modifiers(cls),
                        'superclass': cls.get_superclassname(),
                        'interfaces': cls.get_interfaces(),
                        'methods': [],
                        'fields': [],
                        'inheritance_edges': [],
                        'dependencies': set()
                    }
                    
                    # Extract method information
                    for method in cls.get_methods():
                        method_info = {
                            'name': method.get_name(),
                            'descriptor': method.get_descriptor(),
                            'access_flags': method.get_access_flags(),
                            'opcodes': self._extract_method_opcodes(method),
                            'calls': self._extract_method_calls(method)
                        }
                        class_info['methods'].append(method_info)
                    
                    # Extract field information  
                    for field in cls.get_fields():
                        field_info = {
                            'name': field.get_name(),
                            'descriptor': field.get_descriptor(),
                            'access_flags': field.get_access_flags()
                        }
                        class_info['fields'].append(field_info)
                    
                    class_graph[class_name] = class_info
            
            # Build dependency relationships
            for class_name, class_info in class_graph.items():
                for method_info in class_info['methods']:
                    for call in method_info['calls']:
                        if call in class_graph:
                            class_info['dependencies'].add(call)
                            
        except Exception as e:
            self.logger.error(f"Error building class dependency graph: {str(e)}")
        
        return class_graph
    
    def _extract_method_opcode_patterns(self, dex_objects: List[Any]) -> Dict[str, List[str]]:
        """
        Extract method-opcode patterns for similarity analysis
        
        Args:
            dex_objects: List of DEX objects from androguard
            
        Returns:
            Dictionary mapping method signatures to opcode sequences
        """
        method_patterns = {}
        
        try:
            for dex in dex_objects:
                for cls in dex.get_classes():
                    if self._is_framework_class(cls.get_name()):
                        continue
                    
                    for method in cls.get_methods():
                        method_key = f"{cls.get_name()}.{method.get_name()}{method.get_descriptor()}"
                        opcodes = self._extract_method_opcodes(method)
                        if opcodes:
                            method_patterns[method_key] = opcodes
                            
        except Exception as e:
            self.logger.error(f"Error extracting method opcode patterns: {str(e)}")
        
        return method_patterns
    
    def _extract_call_chain_patterns(self, dex_objects: List[Any]) -> Dict[str, List[str]]:
        """
        Extract call-chain-opcode patterns for similarity analysis
        
        Args:
            dex_objects: List of DEX objects from androguard
            
        Returns:
            Dictionary mapping methods to their call chain patterns
        """
        call_chains = {}
        
        try:
            for dex in dex_objects:
                for cls in dex.get_classes():
                    if self._is_framework_class(cls.get_name()):
                        continue
                    
                    for method in cls.get_methods():
                        method_key = f"{cls.get_name()}.{method.get_name()}"
                        calls = self._extract_method_calls(method)
                        if calls:
                            call_chains[method_key] = calls
                            
        except Exception as e:
            self.logger.error(f"Error extracting call chain patterns: {str(e)}")
        
        return call_chains
    
    def _perform_libscan_matching(self, class_features: Dict[str, Dict[str, Any]], 
                                 method_patterns: Dict[str, List[str]], 
                                 call_chains: Dict[str, List[str]], 
                                 existing_libraries: List[DetectedLibrary]) -> List[DetectedLibrary]:
        """
        Perform LibScan-style similarity matching using extracted features
        
        Args:
            class_features: Class dependency graph features
            method_patterns: Method opcode patterns
            call_chains: Call chain patterns
            existing_libraries: Already detected libraries
            
        Returns:
            List of libraries detected through similarity analysis
        """
        detected_libraries = []
        existing_names = {lib.name.lower() for lib in existing_libraries}
        
        # Define known library signatures for similarity matching
        # This would ideally be loaded from a comprehensive database
        known_signatures = self._get_known_library_signatures()
        
        try:
            for lib_name, signatures in known_signatures.items():
                if lib_name.lower() in existing_names:
                    continue
                
                similarity_score = self._calculate_library_similarity(
                    lib_name, signatures, class_features, method_patterns, call_chains
                )
                
                if similarity_score >= self.similarity_threshold:
                    detected_libraries.append(DetectedLibrary(
                        name=lib_name,
                        confidence=similarity_score,
                        detection_method=LibraryDetectionMethod.SIMILARITY,
                        similarity_score=similarity_score,
                        evidence=[f"Similarity score: {similarity_score:.3f}"]
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error in LibScan matching: {str(e)}")
        
        return detected_libraries
    
    def _calculate_library_similarity(self, lib_name: str, signatures: Dict[str, Any],
                                    class_features: Dict[str, Dict[str, Any]], 
                                    method_patterns: Dict[str, List[str]], 
                                    call_chains: Dict[str, List[str]]) -> float:
        """
        Calculate similarity score between app and library using LibScan approach
        
        Args:
            lib_name: Name of library to check
            signatures: Known signatures for the library
            class_features: App class features
            method_patterns: App method patterns
            call_chains: App call chain patterns
            
        Returns:
            Similarity score between 0 and 1
        """
        total_score = 0.0
        weight_sum = 0.0
        
        try:
            # Method-opcode similarity (weight: 0.4)
            method_sim = self._calculate_method_similarity(signatures.get('methods', {}), method_patterns)
            total_score += method_sim * 0.4
            weight_sum += 0.4
            
            # Call-chain similarity (weight: 0.3) 
            chain_sim = self._calculate_call_chain_similarity(signatures.get('call_chains', {}), call_chains)
            total_score += chain_sim * 0.3
            weight_sum += 0.3
            
            # Structural similarity (weight: 0.3)
            struct_sim = self._calculate_structural_similarity(signatures.get('classes', {}), class_features)
            total_score += struct_sim * 0.3
            weight_sum += 0.3
            
        except Exception as e:
            self.logger.error(f"Error calculating similarity for {lib_name}: {str(e)}")
            return 0.0
        
        return total_score / weight_sum if weight_sum > 0 else 0.0
    
    def _calculate_method_similarity(self, lib_methods: Dict[str, List[str]], 
                                   app_methods: Dict[str, List[str]]) -> float:
        """Calculate method-opcode similarity using set-based inclusion"""
        if not lib_methods or not app_methods:
            return 0.0
        
        matches = 0
        total_lib_methods = len(lib_methods)
        
        for lib_method, lib_opcodes in lib_methods.items():
            best_match = 0.0
            lib_opcode_set = set(lib_opcodes)
            
            for app_method, app_opcodes in app_methods.items():
                app_opcode_set = set(app_opcodes)
                
                # Calculate Jaccard similarity
                intersection = lib_opcode_set.intersection(app_opcode_set)
                union = lib_opcode_set.union(app_opcode_set)
                
                if union:
                    similarity = len(intersection) / len(union)
                    best_match = max(best_match, similarity)
            
            if best_match >= self.class_similarity_threshold:
                matches += 1
        
        return matches / total_lib_methods if total_lib_methods > 0 else 0.0
    
    def _calculate_call_chain_similarity(self, lib_chains: Dict[str, List[str]], 
                                       app_chains: Dict[str, List[str]]) -> float:
        """Calculate call-chain similarity"""
        if not lib_chains or not app_chains:
            return 0.0
        
        matches = 0
        total_lib_chains = len(lib_chains)
        
        for lib_chain, lib_calls in lib_chains.items():
            best_match = 0.0
            lib_call_set = set(lib_calls)
            
            for app_chain, app_calls in app_chains.items():
                app_call_set = set(app_calls)
                
                # Calculate similarity based on call overlap
                intersection = lib_call_set.intersection(app_call_set)
                union = lib_call_set.union(app_call_set)
                
                if union:
                    similarity = len(intersection) / len(union)
                    best_match = max(best_match, similarity)
            
            if best_match >= 0.5:  # Lower threshold for call chains
                matches += 1
        
        return matches / total_lib_chains if total_lib_chains > 0 else 0.0
    
    def _calculate_structural_similarity(self, lib_classes: Dict[str, Dict[str, Any]], 
                                       app_classes: Dict[str, Dict[str, Any]]) -> float:
        """Calculate structural similarity based on class relationships"""
        if not lib_classes or not app_classes:
            return 0.0
        
        matches = 0
        total_lib_classes = len(lib_classes)
        
        for lib_class, lib_info in lib_classes.items():
            best_match = 0.0
            
            for app_class, app_info in app_classes.items():
                similarity = self._compare_class_structure(lib_info, app_info)
                best_match = max(best_match, similarity)
            
            if best_match >= 0.6:  # Threshold for structural similarity
                matches += 1
        
        return matches / total_lib_classes if total_lib_classes > 0 else 0.0
    
    def _compare_class_structure(self, lib_class: Dict[str, Any], app_class: Dict[str, Any]) -> float:
        """Compare two class structures for similarity"""
        score = 0.0
        comparisons = 0
        
        # Compare method count similarity
        lib_methods = lib_class.get('methods', [])
        app_methods = app_class.get('methods', [])
        
        # Handle both integer counts and list formats
        lib_method_count = lib_methods if isinstance(lib_methods, int) else len(lib_methods)
        app_method_count = app_methods if isinstance(app_methods, int) else len(app_methods)
        
        if lib_method_count > 0 and app_method_count > 0:
            method_ratio = min(lib_method_count, app_method_count) / max(lib_method_count, app_method_count)
            score += method_ratio
            comparisons += 1
        
        # Compare field count similarity
        lib_fields = lib_class.get('fields', [])
        app_fields = app_class.get('fields', [])
        
        # Handle both integer counts and list formats
        lib_field_count = lib_fields if isinstance(lib_fields, int) else len(lib_fields)
        app_field_count = app_fields if isinstance(app_fields, int) else len(app_fields)
        
        if lib_field_count > 0 and app_field_count > 0:
            field_ratio = min(lib_field_count, app_field_count) / max(lib_field_count, app_field_count)
            score += field_ratio
            comparisons += 1
        
        return score / comparisons if comparisons > 0 else 0.0
    
    def _get_known_library_signatures(self) -> Dict[str, Dict[str, Any]]:
        """
        Get known library signatures for similarity matching
        
        In a full implementation, this would load from a comprehensive database
        of library signatures. For now, we provide some basic signatures.
        
        Returns:
            Dictionary of library signatures
        """
        return {
            'OkHttp3': {
                'methods': {
                    'okhttp3.OkHttpClient.newCall': ['invoke-virtual', 'move-result-object'],
                    'okhttp3.Request$Builder.build': ['invoke-virtual', 'move-result-object'],
                    'okhttp3.Response.body': ['invoke-virtual', 'move-result-object']
                },
                'call_chains': {
                    'okhttp3.Call.execute': ['okhttp3.RealCall.execute'],
                    'okhttp3.Call.enqueue': ['okhttp3.RealCall.enqueue']
                },
                'classes': {
                    'okhttp3.OkHttpClient': {'methods': 20, 'fields': 5},
                    'okhttp3.Request': {'methods': 8, 'fields': 3},
                    'okhttp3.Response': {'methods': 15, 'fields': 4}
                }
            },
            'Retrofit2': {
                'methods': {
                    'retrofit2.Retrofit$Builder.build': ['invoke-virtual', 'move-result-object'],
                    'retrofit2.Call.execute': ['invoke-interface', 'move-result-object']
                },
                'call_chains': {
                    'retrofit2.Retrofit.create': ['java.lang.reflect.Proxy.newProxyInstance']
                },
                'classes': {
                    'retrofit2.Retrofit': {'methods': 12, 'fields': 6},
                    'retrofit2.Call': {'methods': 4, 'fields': 0}
                }
            },
            'Glide': {
                'methods': {
                    'com.bumptech.glide.Glide.with': ['invoke-static', 'move-result-object'],
                    'com.bumptech.glide.RequestManager.load': ['invoke-virtual', 'move-result-object']
                },
                'call_chains': {
                    'com.bumptech.glide.RequestManager.load': ['com.bumptech.glide.DrawableTypeRequest.into']
                },
                'classes': {
                    'com.bumptech.glide.Glide': {'methods': 25, 'fields': 8},
                    'com.bumptech.glide.RequestManager': {'methods': 30, 'fields': 10}
                }
            }
        }
    
    def _is_framework_class(self, class_name: str) -> bool:
        """Check if a class is part of the Android framework"""
        framework_prefixes = [
            'Landroid/', 'Ljava/', 'Ljavax/', 'Lorg/w3c/', 'Lorg/xml/',
            'Lorg/apache/http/', 'Ldalvik/', 'Llibcore/'
        ]
        return any(class_name.startswith(prefix) for prefix in framework_prefixes)
    
    def _get_class_modifiers(self, cls: Any) -> List[str]:
        """Extract class modifiers (abstract, static, interface, etc.)"""
        modifiers = []
        access_flags = cls.get_access_flags()
        
        # Check common access flags
        if access_flags & 0x1:    # ACC_PUBLIC
            modifiers.append('public')
        if access_flags & 0x2:    # ACC_PRIVATE
            modifiers.append('private')
        if access_flags & 0x4:    # ACC_PROTECTED
            modifiers.append('protected')
        if access_flags & 0x8:    # ACC_STATIC
            modifiers.append('static')
        if access_flags & 0x10:   # ACC_FINAL
            modifiers.append('final')
        if access_flags & 0x400:  # ACC_ABSTRACT
            modifiers.append('abstract')
        if access_flags & 0x200:  # ACC_INTERFACE
            modifiers.append('interface')
        
        return modifiers
    
    def _extract_method_opcodes(self, method: Any) -> List[str]:
        """Extract opcode sequence from a method"""
        opcodes = []
        
        try:
            if method.get_code():
                for instruction in method.get_code().get_bc().get_instructions():
                    opcodes.append(instruction.get_name())
        except Exception:
            pass  # Method might not have code (abstract/native)
        
        return opcodes
    
    def _extract_method_calls(self, method: Any) -> List[str]:
        """Extract method calls from a method"""
        calls = []
        
        try:
            if method.get_code():
                for instruction in method.get_code().get_bc().get_instructions():
                    if instruction.get_name().startswith('invoke-'):
                        # Extract the called method name
                        operands = instruction.get_operands()
                        if operands and len(operands) > 0:
                            # Get the method reference
                            method_ref = operands[-1]
                            if hasattr(method_ref, 'get_class_name') and hasattr(method_ref, 'get_name'):
                                call_target = f"{method_ref.get_class_name()}.{method_ref.get_name()}"
                                calls.append(call_target)
        except Exception:
            pass  # Ignore errors in call extraction
        
        return calls
    
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
                    
                    # Get file size
                    try:
                        file_data = apk.get_file(lib_file)
                        if file_data:
                            lib_groups[lib_name]['size'] += len(file_data)
                    except Exception:
                        pass
            
            # Create DetectedLibrary objects for each native library
            for lib_name, info in lib_groups.items():
                # Determine risk level and description
                risk_level, description = self._assess_native_library_risk(lib_name)
                
                # Clean library name (remove lib prefix and .so suffix)
                clean_name = lib_name.replace('lib', '').replace('.so', '')
                if not clean_name:
                    clean_name = lib_name
                
                native_lib = DetectedLibrary(
                    name=clean_name,
                    library_type=LibraryType.NATIVE_LIBRARY,
                    detection_method=LibraryDetectionMethod.NATIVE,
                    source=LibrarySource.NATIVE_LIBS,
                    location=f"lib/{'/'.join(set(info['architectures']))}",
                    architectures=list(set(info['architectures'])),
                    file_paths=info['paths'],
                    size_bytes=info['size'],
                    risk_level=risk_level,
                    description=description,
                    confidence=0.95,
                    evidence=[f"Native library found: {lib_name}"],
                    category=self._categorize_native_library(lib_name)
                )
                
                native_libraries.append(native_lib)
                
        except Exception as e:
            self.logger.debug(f"Error detecting native libraries: {e}")
            
        return native_libraries
    
    def _detect_androidx_libraries(self, context: AnalysisContext) -> List[DetectedLibrary]:
        """Detect AndroidX libraries through comprehensive smali analysis"""
        androidx_libraries = []
        
        try:
            if not context.androguard_obj:
                return androidx_libraries
                
            apk = context.androguard_obj.get_androguard_apk()
            if not apk:
                return androidx_libraries
            
            # Get all files in the APK
            files = apk.get_files()
            androidx_files = [f for f in files if 'smali' in f and 'androidx' in f and f.endswith('.smali')]
            
            # Group by library package
            androidx_packages = {}
            for file_path in androidx_files:
                # Extract package from path like: smali/androidx/core/app/ActivityCompat.smali
                parts = file_path.split('/')
                if 'androidx' in parts:
                    androidx_idx = parts.index('androidx')
                    if androidx_idx + 2 < len(parts):
                        package = f"androidx.{parts[androidx_idx + 1]}"
                        
                        if package not in androidx_packages:
                            androidx_packages[package] = {
                                'files': [],
                                'classes': set(),
                                'location': f"smali*/androidx/{parts[androidx_idx + 1]}/"
                            }
                        
                        androidx_packages[package]['files'].append(file_path)
                        
                        # Extract class name
                        class_file = parts[-1].replace('.smali', '')
                        androidx_packages[package]['classes'].add(class_file)
            
            # Create DetectedLibrary objects for each AndroidX library
            for package, info in androidx_packages.items():
                version = self._extract_androidx_version(package, info['files'], context)
                age_years = self._calculate_library_age(package, version)
                risk_level = self._assess_androidx_risk(package, version, age_years)
                
                androidx_lib = DetectedLibrary(
                    name=package,
                    package_name=package,
                    version=version,
                    library_type=LibraryType.ANDROIDX,
                    detection_method=LibraryDetectionMethod.SMALI,
                    source=LibrarySource.SMALI_CLASSES,
                    location=info['location'],
                    file_paths=info['files'][:10],  # Limit to first 10 paths
                    risk_level=risk_level,
                    age_years_behind=age_years,
                    description=self._get_androidx_description(package),
                    vendor="Google",
                    confidence=0.98,
                    evidence=[f"AndroidX package found: {package}"],
                    classes_detected=list(info['classes'])[:20],  # Limit to first 20 classes
                    category=LibraryCategory.ANDROIDX
                )
                
                androidx_libraries.append(androidx_lib)
                
        except Exception as e:
            self.logger.debug(f"Error detecting AndroidX libraries: {e}")
            
        return androidx_libraries
    
    def _assess_native_library_risk(self, lib_name: str) -> tuple:
        """Assess risk level for native libraries"""
        lib_lower = lib_name.lower()
        
        # Critical risk libraries
        if any(pattern in lib_lower for pattern in ['encrypt', 'crypt', 'obfuscat', 'protect']):
            return RiskLevel.CRITICAL, "Custom encryption/obfuscation library (security risk)"
        
        # High risk libraries    
        if any(pattern in lib_lower for pattern in ['ffmpeg', 'avcodec', 'avformat', 'avutil']):
            return RiskLevel.HIGH, "Media processing library (potential vulnerabilities)"
        
        if any(pattern in lib_lower for pattern in ['analytics', 'crash', 'report']):
            return RiskLevel.HIGH, "Analytics/crash reporting library"
        
        # Medium risk libraries
        if any(pattern in lib_lower for pattern in ['image', 'gif', 'png', 'jpg', 'filter']):
            return RiskLevel.MEDIUM, "Image processing library"
        
        if any(pattern in lib_lower for pattern in ['player', 'audio', 'video']):
            return RiskLevel.MEDIUM, "Media player library"
        
        # Low risk by default
        return RiskLevel.LOW, "Native library"
    
    def _categorize_native_library(self, lib_name: str) -> LibraryCategory:
        """Categorize native libraries"""
        lib_lower = lib_name.lower()
        
        if any(pattern in lib_lower for pattern in ['ffmpeg', 'avcodec', 'avformat', 'avutil', 'player']):
            return LibraryCategory.MEDIA
        
        if any(pattern in lib_lower for pattern in ['analytics', 'crash']):
            return LibraryCategory.ANALYTICS
        
        if any(pattern in lib_lower for pattern in ['encrypt', 'crypt']):
            return LibraryCategory.SECURITY
        
        if any(pattern in lib_lower for pattern in ['image', 'gif', 'png']):
            return LibraryCategory.UI_FRAMEWORK
        
        return LibraryCategory.UTILITY
    
    def _extract_androidx_version(self, package: str, files: List[str], context: AnalysisContext) -> Optional[str]:
        """Extract AndroidX library version from various sources"""
        try:
            # Try to find version from build config or constants
            for file_path in files[:5]:  # Check first few files
                try:
                    apk = context.androguard_obj.get_apk()
                    file_content = apk.get_file(file_path)
                    if file_content:
                        content_str = file_content.decode('utf-8', errors='ignore')
                        # Look for version patterns
                        version_patterns = [
                            r'VERSION_NAME\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
                            r'version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
                            r'androidx[/\.][\w\.]+:([0-9]+\.[0-9]+\.[0-9]+[^"]*)',
                        ]
                        
                        for pattern in version_patterns:
                            import re
                            match = re.search(pattern, content_str)
                            if match:
                                return match.group(1)
                except Exception:
                    continue
            
            # Fallback to known versions based on patterns
            return self._get_androidx_known_version(package)
            
        except Exception as e:
            self.logger.debug(f"Error extracting AndroidX version for {package}: {e}")
            return None
    
    def _get_androidx_known_version(self, package: str) -> Optional[str]:
        """Get known version patterns for AndroidX libraries"""
        # This would ideally come from a database of known library versions
        version_mappings = {
            'androidx.core': '1.9.0',
            'androidx.appcompat': '1.3.1', 
            'androidx.lifecycle': '2.3.1',
            'androidx.room': '2.3.0',
            'androidx.fragment': '1.3.6',
            'androidx.recyclerview': '1.2.1',
            'androidx.datastore': '1.0.0',
            'androidx.sqlite': '2.1.0',
            'androidx.activity': '1.2.4',
            'androidx.browser': '1.3.0'
        }
        return version_mappings.get(package)
    
    def _calculate_library_age(self, package: str, version: str) -> Optional[float]:
        """Calculate how many years behind the current version this library is"""
        if not version:
            return None
            
        # This would ideally connect to a real database of library releases
        # For now, use some heuristics based on version patterns
        try:
            # Simple heuristic: older version numbers tend to be older
            if version.startswith('1.'):
                return 3.0  # Assume 3 years old
            elif version.startswith('2.0') or version.startswith('2.1'):
                return 2.0  # Assume 2 years old
            elif version.startswith('2.3'):
                return 1.5  # Assume 1.5 years old
            else:
                return 1.0  # Assume 1 year old
                
        except Exception:
            return None
    
    def _assess_androidx_risk(self, package: str, version: str, age_years: Optional[float]) -> RiskLevel:
        """Assess risk level for AndroidX libraries"""
        if not age_years:
            return RiskLevel.UNKNOWN
            
        if age_years >= 4:
            return RiskLevel.HIGH
        elif age_years >= 3:
            return RiskLevel.MEDIUM  
        elif age_years >= 2:
            return RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    def _get_androidx_description(self, package: str) -> str:
        """Get description for AndroidX libraries"""
        descriptions = {
            'androidx.core': 'AndroidX core components and utilities',
            'androidx.appcompat': 'AppCompat library for backward compatibility',
            'androidx.lifecycle': 'Lifecycle-aware components',
            'androidx.room': 'Room persistence library',
            'androidx.fragment': 'Fragment framework',
            'androidx.recyclerview': 'RecyclerView widget',
            'androidx.datastore': 'DataStore for data storage',
            'androidx.sqlite': 'SQLite framework',
            'androidx.activity': 'Activity framework',
            'androidx.browser': 'Custom Tabs support'
        }
        return descriptions.get(package, 'AndroidX library component')
    
    def generate_comprehensive_report(self, libraries: List[DetectedLibrary]) -> str:
        """Generate a comprehensive library report similar to libs.txt format"""
        if not libraries:
            return "No libraries detected in this APK."
        
        report_lines = []
        report_lines.append("Library Name                          Version    Location                                    Age (Years Behind)")
        report_lines.append("=" * 105)
        report_lines.append("")
        
        # Group libraries by type
        androidx_libs = [lib for lib in libraries if lib.library_type == LibraryType.ANDROIDX]
        native_libs = [lib for lib in libraries if lib.library_type == LibraryType.NATIVE_LIBRARY] 
        third_party_libs = [lib for lib in libraries if lib.library_type == LibraryType.THIRD_PARTY_SDK]
        
        # AndroidX Libraries section
        if androidx_libs:
            report_lines.append("ANDROIDX LIBRARIES")
            report_lines.append("=" * 105)
            for lib in sorted(androidx_libs, key=lambda x: x.name):
                version = lib.version or "Unknown"
                location = lib.location or "Unknown location"
                age = lib.get_age_description()
                report_lines.append(f"{lib.name:<35} {version:<10} {location:<40} {age}")
            report_lines.append("")
        
        # Native Libraries section  
        if native_libs:
            report_lines.append("NATIVE LIBRARIES (.so files)")
            report_lines.append("=" * 105)
            for lib in sorted(native_libs, key=lambda x: x.name):
                version = lib.version or "Unknown"
                location = lib.location or "Unknown location"
                risk_desc = lib.get_risk_description()
                report_lines.append(f"{lib.name:<35} {version:<10} {location:<40} {risk_desc}")
            report_lines.append("")
        
        # Third-party SDKs section
        if third_party_libs:
            report_lines.append("THIRD-PARTY SDKS")
            report_lines.append("=" * 105)
            for lib in sorted(third_party_libs, key=lambda x: x.name):
                version = lib.version or "Unknown"
                location = lib.location or "Unknown location"
                age = lib.get_age_description()
                report_lines.append(f"{lib.name:<35} {version:<10} {location:<40} {age}")
            report_lines.append("")
        
        # Security Risk Summary
        critical_libs = [lib for lib in libraries if lib.risk_level == RiskLevel.CRITICAL]
        high_libs = [lib for lib in libraries if lib.risk_level == RiskLevel.HIGH]
        medium_libs = [lib for lib in libraries if lib.risk_level == RiskLevel.MEDIUM]
        low_libs = [lib for lib in libraries if lib.risk_level == RiskLevel.LOW]
        
        report_lines.append("SECURITY RISK SUMMARY")
        report_lines.append("=" * 105)
        report_lines.append(f"Total Libraries Identified: {len(libraries)}")
        report_lines.append(f"Critical Risk Libraries: {len(critical_libs)}")
        report_lines.append(f"High Risk Libraries: {len(high_libs)}")
        report_lines.append(f"Medium Risk Libraries: {len(medium_libs)}")
        report_lines.append(f"Low Risk Libraries: {len(low_libs)}")
        report_lines.append("")
        
        # Age Distribution
        aged_libs = [lib for lib in libraries if lib.age_years_behind is not None]
        if aged_libs:
            one_year = len([lib for lib in aged_libs if lib.age_years_behind < 1])
            two_years = len([lib for lib in aged_libs if 1 <= lib.age_years_behind < 2])  
            three_years = len([lib for lib in aged_libs if 2 <= lib.age_years_behind < 3])
            four_plus_years = len([lib for lib in aged_libs if lib.age_years_behind >= 3])
            
            report_lines.append("Age Distribution:")
            report_lines.append(f"- Current: {one_year} libraries")
            report_lines.append(f"- 1 year behind: {two_years} libraries")
            report_lines.append(f"- 2 years behind: {three_years} libraries") 
            report_lines.append(f"- 3+ years behind: {four_plus_years} libraries")
            report_lines.append("")
        
        from datetime import datetime
        report_lines.append(f"Analysis Date: {datetime.now().strftime('%B %Y')}")
        
        # Overall risk assessment
        if critical_libs or len(high_libs) > 5:
            risk_assessment = "HIGH (Critical vulnerabilities present)"
        elif len(high_libs) > 2 or len(medium_libs) > 10:
            risk_assessment = "MEDIUM (Significant technical debt)"
        else:
            risk_assessment = "LOW (Libraries appear current)"
            
        report_lines.append(f"Risk Assessment: {risk_assessment}")
        
        return "\n".join(report_lines)
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        if not isinstance(self.confidence_threshold, (int, float)) or not (0 <= self.confidence_threshold <= 1):
            self.logger.error("confidence_threshold must be a number between 0 and 1")
            return False
        
        if not isinstance(self.similarity_threshold, (int, float)) or not (0 <= self.similarity_threshold <= 1):
            self.logger.error("similarity_threshold must be a number between 0 and 1")
            return False
        
        return True