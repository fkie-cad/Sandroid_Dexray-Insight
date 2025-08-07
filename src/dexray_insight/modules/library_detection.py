#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module
from ..results.LibraryDetectionResults import DetectedLibrary, LibraryDetectionMethod, LibraryCategory

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
            
            # Remove duplicates based on name and package
            detected_libraries = self._deduplicate_libraries(detected_libraries)
            
            execution_time = time.time() - start_time
            
            self.logger.info(f"Library detection completed: {len(detected_libraries)} unique libraries detected")
            self.logger.info(f"Total execution time: {execution_time:.2f}s (Stage 1: {stage1_time:.2f}s, Stage 2: {stage2_time:.2f}s)")
            
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
        lib_method_count = len(lib_class.get('methods', []))
        app_method_count = len(app_class.get('methods', []))
        
        if lib_method_count > 0 and app_method_count > 0:
            method_ratio = min(lib_method_count, app_method_count) / max(lib_method_count, app_method_count)
            score += method_ratio
            comparisons += 1
        
        # Compare field count similarity
        lib_field_count = len(lib_class.get('fields', []))
        app_field_count = len(app_class.get('fields', []))
        
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
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        if not isinstance(self.confidence_threshold, (int, float)) or not (0 <= self.confidence_threshold <= 1):
            self.logger.error("confidence_threshold must be a number between 0 and 1")
            return False
        
        if not isinstance(self.similarity_threshold, (int, float)) or not (0 <= self.similarity_threshold <= 1):
            self.logger.error("similarity_threshold must be a number between 0 and 1")
            return False
        
        return True