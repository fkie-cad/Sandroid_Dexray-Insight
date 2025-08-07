#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import re
import requests
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module

@dataclass
class DetectedTracker:
    """Container for a detected tracker with metadata"""
    name: str
    version: Optional[str] = None
    description: str = ""
    category: str = ""
    website: str = ""
    code_signature: str = ""
    network_signature: str = ""
    detection_method: str = ""
    locations: List[str] = None
    confidence: float = 1.0
    
    def __post_init__(self):
        if self.locations is None:
            self.locations = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'category': self.category,
            'website': self.website,
            'code_signature': self.code_signature,
            'network_signature': self.network_signature,
            'detection_method': self.detection_method,
            'locations': self.locations,
            'confidence': self.confidence
        }

@dataclass
class TrackerAnalysisResult(BaseResult):
    """Result class for tracker analysis"""
    detected_trackers: List[DetectedTracker] = None
    total_trackers: int = 0
    exodus_trackers: List[Dict[str, Any]] = None
    custom_detections: List[DetectedTracker] = None
    analysis_errors: List[str] = None
    
    def __post_init__(self):
        if self.detected_trackers is None:
            self.detected_trackers = []
        if self.custom_detections is None:
            self.custom_detections = []
        if self.analysis_errors is None:
            self.analysis_errors = []
        self.total_trackers = len(self.detected_trackers)
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'detected_trackers': [tracker.to_dict() for tracker in self.detected_trackers],
            'total_trackers': self.total_trackers,
            'custom_detections': [tracker.to_dict() for tracker in self.custom_detections],
            'analysis_errors': self.analysis_errors
        })
        return base_dict

@register_module('tracker_analysis')
class TrackerAnalysisModule(BaseAnalysisModule):
    """Tracker detection module for identifying advertising and analytics SDKs in APKs"""
    
    # Comprehensive tracker database with patterns and metadata
    TRACKER_DATABASE = {
        # Google/Alphabet trackers
        'Google AdMob': {
            'patterns': [
                r'com\.google\.android\.gms\.ads',
                r'com\.google\.ads',
                r'googleads\.g\.doubleclick\.net',
                r'admob\.com'
            ],
            'version_patterns': [
                r'GoogleMobileAdsPlugin\.(\d+\.\d+\.\d+)',
                r'admob-(\d+\.\d+\.\d+)',
                r'gms\.ads\.version\.(\d+\.\d+\.\d+)'
            ],
            'description': 'Google AdMob mobile advertising platform',
            'category': 'Advertising',
            'website': 'https://admob.google.com',
            'network_patterns': [r'googleads\.g\.doubleclick\.net', r'admob\.com']
        },
        'Google Analytics': {
            'patterns': [
                r'com\.google\.android\.gms\.analytics',
                r'com\.google\.analytics',
                r'google-analytics\.com'
            ],
            'version_patterns': [
                r'analytics\.(\d+\.\d+\.\d+)',
                r'gms\.analytics\.version\.(\d+\.\d+\.\d+)'
            ],
            'description': 'Google Analytics mobile app analytics',
            'category': 'Analytics',
            'website': 'https://analytics.google.com',
            'network_patterns': [r'google-analytics\.com', r'ssl\.google-analytics\.com']
        },
        'Google Firebase Analytics': {
            'patterns': [
                r'com\.google\.firebase\.analytics',
                r'com\.google\.android\.gms\.measurement',
                r'firebase\.google\.com'
            ],
            'version_patterns': [
                r'firebase-analytics[_-](\d+\.\d+\.\d+)',
                r'measurement\.(\d+\.\d+\.\d+)'
            ],
            'description': 'Firebase Analytics for mobile apps',
            'category': 'Analytics',
            'website': 'https://firebase.google.com/products/analytics',
            'network_patterns': [r'firebase\.google\.com', r'app-measurement\.com']
        },
        'Google DoubleClick': {
            'patterns': [
                r'com\.google\.android\.gms\.ads\.doubleclick',
                r'doubleclick\.net',
                r'googlesyndication\.com'
            ],
            'version_patterns': [
                r'doubleclick[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Google DoubleClick ad serving platform',
            'category': 'Advertising',
            'website': 'https://marketingplatform.google.com/about/doubleclick/',
            'network_patterns': [r'doubleclick\.net', r'googlesyndication\.com']
        },
        
        # Facebook/Meta trackers
        'Facebook SDK': {
            'patterns': [
                r'com\.facebook\.android',
                r'com\.facebook\.sdk',
                r'graph\.facebook\.com'
            ],
            'version_patterns': [
                r'FacebookSdk[_-](\d+\.\d+\.\d+)',
                r'facebook-android-sdk[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Facebook SDK for Android',
            'category': 'Social/Analytics',
            'website': 'https://developers.facebook.com/docs/android/',
            'network_patterns': [r'graph\.facebook\.com', r'connect\.facebook\.net']
        },
        'Facebook Analytics': {
            'patterns': [
                r'com\.facebook\.appevents',
                r'com\.facebook\.analytics',
                r'graph\.facebook\.com.*events'
            ],
            'version_patterns': [
                r'facebook-analytics[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Facebook Analytics and App Events',
            'category': 'Analytics',
            'website': 'https://developers.facebook.com/docs/app-events/',
            'network_patterns': [r'graph\.facebook\.com']
        },
        
        # Amazon trackers
        'Amazon Mobile Ads': {
            'patterns': [
                r'com\.amazon\.device\.ads',
                r'amazon-adsystem\.com'
            ],
            'version_patterns': [
                r'amazon-ads[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Amazon Mobile Ad Network',
            'category': 'Advertising',
            'website': 'https://advertising.amazon.com/solutions/products/mobile-ads',
            'network_patterns': [r'amazon-adsystem\.com']
        },
        
        # Unity trackers
        'Unity Ads': {
            'patterns': [
                r'com\.unity3d\.ads',
                r'unityads\.unity3d\.com'
            ],
            'version_patterns': [
                r'unity-ads[_-](\d+\.\d+\.\d+)',
                r'UnityAds\.(\d+\.\d+\.\d+)'
            ],
            'description': 'Unity Ads mobile advertising platform',
            'category': 'Advertising',
            'website': 'https://unity.com/products/unity-ads',
            'network_patterns': [r'unityads\.unity3d\.com']
        },
        'Unity Analytics': {
            'patterns': [
                r'com\.unity3d\.services\.analytics',
                r'analytics\.cloud\.unity3d\.com'
            ],
            'version_patterns': [
                r'unity-analytics[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Unity Analytics for game analytics',
            'category': 'Analytics',
            'website': 'https://unity.com/products/unity-analytics',
            'network_patterns': [r'analytics\.cloud\.unity3d\.com']
        },
        
        # AppLovin trackers
        'AppLovin': {
            'patterns': [
                r'com\.applovin',
                r'applovin\.com'
            ],
            'version_patterns': [
                r'applovin[_-](\d+\.\d+\.\d+)',
                r'AppLovinSdk[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'AppLovin mobile advertising and analytics',
            'category': 'Advertising',
            'website': 'https://www.applovin.com/',
            'network_patterns': [r'applovin\.com', r'ms\.applovin\.com']
        },
        
        # Flurry (Verizon Media/Yahoo)
        'Flurry Analytics': {
            'patterns': [
                r'com\.flurry\.android',
                r'flurry\.com'
            ],
            'version_patterns': [
                r'flurry[_-]analytics[_-](\d+\.\d+\.\d+)',
                r'FlurryAgent[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Flurry mobile analytics platform',
            'category': 'Analytics',
            'website': 'https://developer.yahoo.com/flurry/',
            'network_patterns': [r'flurry\.com', r'data\.flurry\.com']
        },
        
        # MoPub (Twitter)
        'MoPub': {
            'patterns': [
                r'com\.mopub',
                r'mopub\.com'
            ],
            'version_patterns': [
                r'mopub[_-](\d+\.\d+\.\d+)',
                r'MoPubSdk[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'MoPub mobile advertising platform',
            'category': 'Advertising',
            'website': 'https://www.mopub.com/',
            'network_patterns': [r'mopub\.com', r'ads\.mopub\.com']
        },
        
        # Crashlytics
        'Firebase Crashlytics': {
            'patterns': [
                r'com\.google\.firebase\.crashlytics',
                r'com\.crashlytics',
                r'crashlytics\.com'
            ],
            'version_patterns': [
                r'crashlytics[_-](\d+\.\d+\.\d+)',
                r'firebase-crashlytics[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Firebase Crashlytics crash reporting',
            'category': 'Crash Reporting',
            'website': 'https://firebase.google.com/products/crashlytics',
            'network_patterns': [r'crashlytics\.com', r'firebase\.google\.com']
        },
        
        # AdColony
        'AdColony': {
            'patterns': [
                r'com\.adcolony',
                r'adcolony\.com'
            ],
            'version_patterns': [
                r'adcolony[_-](\d+\.\d+\.\d+)',
                r'AdColony[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'AdColony video advertising platform',
            'category': 'Advertising',
            'website': 'https://www.adcolony.com/',
            'network_patterns': [r'adcolony\.com', r'ads30\.adcolony\.com']
        },
        
        # Vungle
        'Vungle': {
            'patterns': [
                r'com\.vungle',
                r'vungle\.com'
            ],
            'version_patterns': [
                r'vungle[_-](\d+\.\d+\.\d+)',
                r'VungleSDK[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Vungle video advertising platform',
            'category': 'Advertising',
            'website': 'https://vungle.com/',
            'network_patterns': [r'vungle\.com', r'api\.vungle\.com']
        },
        
        # ChartBoost
        'Chartboost': {
            'patterns': [
                r'com\.chartboost',
                r'chartboost\.com'
            ],
            'version_patterns': [
                r'chartboost[_-](\d+\.\d+\.\d+)',
                r'Chartboost[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Chartboost mobile game advertising',
            'category': 'Advertising',
            'website': 'https://www.chartboost.com/',
            'network_patterns': [r'chartboost\.com', r'live\.chartboost\.com']
        },
        
        # IronSource
        'ironSource': {
            'patterns': [
                r'com\.ironsource',
                r'ironsrc\.com'
            ],
            'version_patterns': [
                r'ironsource[_-](\d+\.\d+\.\d+)',
                r'IronSource[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'ironSource mobile advertising and monetization',
            'category': 'Advertising',
            'website': 'https://www.ironsrc.com/',
            'network_patterns': [r'ironsrc\.com', r'init\.supersonicads\.com']
        },
        
        # Tapjoy
        'Tapjoy': {
            'patterns': [
                r'com\.tapjoy',
                r'tapjoy\.com'
            ],
            'version_patterns': [
                r'tapjoy[_-](\d+\.\d+\.\d+)',
                r'Tapjoy[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Tapjoy mobile advertising and rewards',
            'category': 'Advertising',
            'website': 'https://www.tapjoy.com/',
            'network_patterns': [r'tapjoy\.com', r'ws\.tapjoyads\.com']
        },
        
        # Exodus Privacy patterns (from their API research)
        'Teemo': {
            'patterns': [
                r'com\.databerries\.',
                r'com\.geolocstation\.',
                r'databerries\.com'
            ],
            'version_patterns': [
                r'teemo[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Teemo geolocation tracking SDK',
            'category': 'Location Tracking',
            'website': 'https://www.teemo.co/',
            'network_patterns': [r'databerries\.com']
        },
        'FidZup': {
            'patterns': [
                r'com\.fidzup\.',
                r'fidzup'
            ],
            'version_patterns': [
                r'fidzup[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'FidZup sonic geolocation tracking',
            'category': 'Location Tracking',
            'website': 'https://www.fidzup.com/',
            'network_patterns': [r'fidzup\.com']
        },
        'Audience Studio (Krux)': {
            'patterns': [
                r'com\.krux\.androidsdk',
                r'krxd\.net'
            ],
            'version_patterns': [
                r'krux[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Salesforce Audience Studio (formerly Krux) data management platform',
            'category': 'Data Management',
            'website': 'https://www.salesforce.com/products/marketing-cloud/data-management/',
            'network_patterns': [r'krxd\.net']
        },
        'Ad4Screen': {
            'patterns': [
                r'com\.ad4screen\.sdk',
                r'a4\.tl',
                r'accengage\.com',
                r'ad4push\.com',
                r'ad4screen\.com'
            ],
            'version_patterns': [
                r'ad4screen[_-](\d+\.\d+\.\d+)'
            ],
            'description': 'Ad4Screen (Accengage) mobile advertising and push notifications',
            'category': 'Advertising',
            'website': 'https://www.accengage.com/',
            'network_patterns': [r'a4\.tl', r'accengage\.com', r'ad4push\.com', r'ad4screen\.com']
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.exodus_api_url = config.get('exodus_api_url', 'https://reports.exodus-privacy.eu.org/api/trackers')
        self.fetch_exodus_trackers = config.get('fetch_exodus_trackers', True)
        self.timeout = config.get('api_timeout', 10)
        self.exodus_trackers_cache = None
    
    def get_dependencies(self) -> List[str]:
        """Dependencies: string analysis for pattern matching"""
        return ['string_analysis']
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> TrackerAnalysisResult:
        """
        Perform tracker detection analysis on the APK
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context with previous analysis results
            
        Returns:
            TrackerAnalysisResult with detected trackers
        """
        start_time = time.time()
        
        self.logger.info(f"Starting tracker analysis for {apk_path}")
        
        try:
            detected_trackers = []
            analysis_errors = []
            exodus_trackers = []
            custom_detections = []
            
            # Get strings from string analysis module
            string_analysis = context.get_result('string_analysis')
            if not string_analysis:
                self.logger.warning("String analysis results not available, limited tracker detection")
                all_strings = set()
            else:
                all_strings = set()
                # Collect all strings from different categories
                if hasattr(string_analysis, 'urls') and string_analysis.urls:
                    all_strings.update(string_analysis.urls)
                if hasattr(string_analysis, 'domains') and string_analysis.domains:
                    all_strings.update(string_analysis.domains)
                if hasattr(string_analysis, 'emails') and string_analysis.emails:
                    all_strings.update(string_analysis.emails)
                
                # Also get raw strings from androguard if available
                # Store string-to-location mapping for detailed results
                string_locations = {}
                if context.androguard_obj:
                    try:
                        dex_obj = context.androguard_obj.get_androguard_dex()
                        if dex_obj:
                            for dex in dex_obj:
                                # Extract strings with class/method context
                                for class_analysis in dex.get_classes():
                                    class_name = class_analysis.get_name()
                                    for method in class_analysis.get_methods():
                                        method_name = method.get_name()
                                        method_full_name = f"{class_name}->{method_name}"
                                        
                                        # Get strings from method bytecode
                                        try:
                                            for instruction in method.get_instructions():
                                                if hasattr(instruction, 'get_operands'):
                                                    for operand in instruction.get_operands():
                                                        if hasattr(operand, 'get_value'):
                                                            operand_value = operand.get_value()
                                                            if isinstance(operand_value, str) and len(operand_value) > 3:
                                                                all_strings.add(operand_value)
                                                                if operand_value not in string_locations:
                                                                    string_locations[operand_value] = []
                                                                string_locations[operand_value].append(method_full_name)
                                        except Exception:
                                            pass  # Skip errors in instruction parsing
                                
                                # Also get all strings from DEX (fallback)
                                for string in dex.get_strings():
                                    string_value = str(string)
                                    all_strings.add(string_value)
                                    # If no specific location found, mark as generic
                                    if string_value not in string_locations:
                                        string_locations[string_value] = ["DEX strings pool"]
                    except Exception as e:
                        self.logger.warning(f"Error extracting raw strings: {str(e)}")
                        # Fallback to simple string extraction
                        try:
                            dex_obj = context.androguard_obj.get_androguard_dex()
                            if dex_obj:
                                for dex in dex_obj:
                                    for string in dex.get_strings():
                                        string_value = str(string)
                                        all_strings.add(string_value)
                                        string_locations[string_value] = ["DEX strings pool"]
                        except Exception:
                            pass
                
                # Store string locations in context for use in pattern matching
                context.string_locations = string_locations
            
            self.logger.debug(f"Analyzing {len(all_strings)} strings for tracker patterns")
            
            # Fetch Exodus Privacy trackers if enabled
            if self.fetch_exodus_trackers:
                try:
                    exodus_trackers = self._fetch_exodus_trackers()
                    self.logger.debug(f"Loaded {len(exodus_trackers)} trackers from Exodus Privacy")
                except Exception as e:
                    error_msg = f"Failed to fetch Exodus Privacy trackers: {str(e)}"
                    self.logger.warning(error_msg)
                    analysis_errors.append(error_msg)
            
            # Detect trackers using built-in database
            custom_detections = self._detect_custom_trackers(all_strings, context)
            detected_trackers.extend(custom_detections)
            
            # Detect trackers using Exodus Privacy patterns
            if exodus_trackers:
                exodus_detections = self._detect_exodus_trackers(all_strings, exodus_trackers, context)
                detected_trackers.extend(exodus_detections)
            
            # Remove duplicates based on tracker name
            unique_trackers = self._deduplicate_trackers(detected_trackers)
            
            execution_time = time.time() - start_time
            
            # Log summary
            self.logger.info(f"Tracker analysis completed: {len(unique_trackers)} trackers detected")
            for tracker in unique_trackers:
                version_info = f" (v{tracker.version})" if tracker.version else ""
                self.logger.info(f"📍 {tracker.name}{version_info} - {tracker.category}")
            
            return TrackerAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                detected_trackers=unique_trackers,
                total_trackers=len(unique_trackers),
                custom_detections=custom_detections,
                analysis_errors=analysis_errors
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Tracker analysis failed: {str(e)}")
            
            return TrackerAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                total_trackers=0,
                analysis_errors=[str(e)]
            )
    
    def _fetch_exodus_trackers(self) -> List[Dict[str, Any]]:
        """Fetch tracker signatures from Exodus Privacy API"""
        if self.exodus_trackers_cache:
            return self.exodus_trackers_cache
        
        try:
            response = requests.get(self.exodus_api_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            trackers = []
            
            # Process the API response
            if isinstance(data, dict) and 'trackers' in data:
                for tracker_id, tracker_info in data['trackers'].items():
                    trackers.append({
                        'id': tracker_id,
                        'name': tracker_info.get('name', f'Unknown Tracker {tracker_id}'),
                        'description': tracker_info.get('description', ''),
                        'category': tracker_info.get('category', 'Unknown'),
                        'website': tracker_info.get('website', ''),
                        'code_signature': tracker_info.get('code_signature', ''),
                        'network_signature': tracker_info.get('network_signature', '')
                    })
            
            self.exodus_trackers_cache = trackers
            return trackers
            
        except Exception as e:
            self.logger.error(f"Failed to fetch Exodus trackers: {str(e)}")
            raise
    
    def _detect_custom_trackers(self, strings: Set[str], context: AnalysisContext) -> List[DetectedTracker]:
        """Detect trackers using built-in tracker database"""
        detected = []
        
        for tracker_name, tracker_info in self.TRACKER_DATABASE.items():
            detection_results = self._check_tracker_patterns(
                tracker_name, tracker_info, strings, context
            )
            if detection_results:
                detected.extend(detection_results)
        
        return detected
    
    def _detect_exodus_trackers(self, strings: Set[str], exodus_trackers: List[Dict[str, Any]], context: AnalysisContext) -> List[DetectedTracker]:
        """Detect trackers using Exodus Privacy patterns"""
        detected = []
        
        for tracker_info in exodus_trackers:
            code_signature = tracker_info.get('code_signature', '')
            network_signature = tracker_info.get('network_signature', '')
            
            if not code_signature and not network_signature:
                continue
            
            # Check code signatures
            code_matches = []
            detailed_locations = []
            if code_signature:
                try:
                    code_pattern = re.compile(code_signature, re.IGNORECASE)
                    for string in strings:
                        if code_pattern.search(string):
                            code_matches.append(string)
                            # Add location details if available
                            if hasattr(context, 'string_locations') and string in context.string_locations:
                                for location in context.string_locations[string][:3]:  # Limit to 3 locations per string
                                    detailed_locations.append(f"{string} -> {location}")
                            else:
                                detailed_locations.append(string)
                except re.error:
                    self.logger.warning(f"Invalid regex pattern in Exodus tracker {tracker_info['name']}: {code_signature}")
            
            # Check network signatures
            network_matches = []
            if network_signature:
                try:
                    network_pattern = re.compile(network_signature, re.IGNORECASE)
                    for string in strings:
                        if network_pattern.search(string):
                            network_matches.append(string)
                            # Add location details if available
                            if hasattr(context, 'string_locations') and string in context.string_locations:
                                for location in context.string_locations[string][:3]:  # Limit to 3 locations per string
                                    detailed_locations.append(f"{string} -> {location}")
                            else:
                                detailed_locations.append(string)
                except re.error:
                    self.logger.warning(f"Invalid network regex pattern in Exodus tracker {tracker_info['name']}: {network_signature}")
            
            # If matches found, create detection
            if code_matches or network_matches:
                tracker = DetectedTracker(
                    name=tracker_info['name'],
                    description=tracker_info.get('description', ''),
                    category=tracker_info.get('category', 'Unknown'),
                    website=tracker_info.get('website', ''),
                    code_signature=code_signature,
                    network_signature=network_signature,
                    detection_method='Exodus Privacy API',
                    locations=detailed_locations[:10],  # Limit to first 10 detailed locations
                    confidence=0.9  # Slightly lower confidence for Exodus patterns
                )
                detected.append(tracker)
        
        return detected
    
    def _check_tracker_patterns(self, tracker_name: str, tracker_info: Dict[str, Any], strings: Set[str], context: AnalysisContext) -> List[DetectedTracker]:
        """Check if tracker patterns match in the strings"""
        patterns = tracker_info.get('patterns', [])
        version_patterns = tracker_info.get('version_patterns', [])
        network_patterns = tracker_info.get('network_patterns', [])
        
        matches = []
        version = None
        detailed_locations = []
        
        # Check code patterns
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for string in strings:
                    if regex.search(string):
                        matches.append(string)
                        # Add location details if available
                        if hasattr(context, 'string_locations') and string in context.string_locations:
                            for location in context.string_locations[string][:3]:  # Limit to 3 locations per string
                                detailed_locations.append(f"{string} -> {location}")
                        else:
                            detailed_locations.append(string)
            except re.error:
                self.logger.warning(f"Invalid regex pattern for {tracker_name}: {pattern}")
        
        # Check network patterns
        for pattern in network_patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for string in strings:
                    if regex.search(string):
                        matches.append(string)
                        # Add location details if available
                        if hasattr(context, 'string_locations') and string in context.string_locations:
                            for location in context.string_locations[string][:3]:  # Limit to 3 locations per string
                                detailed_locations.append(f"{string} -> {location}")
                        else:
                            detailed_locations.append(string)
            except re.error:
                self.logger.warning(f"Invalid network regex pattern for {tracker_name}: {pattern}")
        
        # If matches found, try to extract version
        if matches:
            version = self._extract_version(matches, version_patterns)
            
            tracker = DetectedTracker(
                name=tracker_name,
                version=version,
                description=tracker_info.get('description', ''),
                category=tracker_info.get('category', 'Unknown'),
                website=tracker_info.get('website', ''),
                code_signature='|'.join(patterns),
                network_signature='|'.join(network_patterns),
                detection_method='Built-in Database',
                locations=list(set(detailed_locations))[:10],  # Deduplicate and limit
                confidence=1.0
            )
            return [tracker]
        
        return []
    
    def _extract_version(self, matches: List[str], version_patterns: List[str]) -> Optional[str]:
        """Extract version information from matched strings"""
        for pattern in version_patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for match in matches:
                    version_match = regex.search(match)
                    if version_match:
                        return version_match.group(1)
            except (re.error, IndexError):
                continue
        
        # Fallback: look for common version patterns in matches
        fallback_patterns = [
            r'(\d+\.\d+\.\d+)',  # Standard semantic versioning
            r'v(\d+\.\d+\.\d+)',  # Version with v prefix
            r'(\d+\.\d+)',        # Major.minor versioning
        ]
        
        for pattern in fallback_patterns:
            try:
                regex = re.compile(pattern)
                for match in matches:
                    version_match = regex.search(match)
                    if version_match:
                        return version_match.group(1)
            except (re.error, IndexError):
                continue
        
        return None
    
    def _deduplicate_trackers(self, trackers: List[DetectedTracker]) -> List[DetectedTracker]:
        """Remove duplicate trackers based on name, keeping the one with highest confidence"""
        unique_trackers = {}
        
        for tracker in trackers:
            existing = unique_trackers.get(tracker.name)
            if not existing or tracker.confidence > existing.confidence:
                unique_trackers[tracker.name] = tracker
            elif existing and tracker.version and not existing.version:
                # Keep version info if available
                existing.version = tracker.version
                existing.locations.extend(tracker.locations)
                existing.locations = list(set(existing.locations))[:10]
        
        return list(unique_trackers.values())
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        if self.timeout <= 0:
            self.logger.warning("API timeout should be positive")
            return False
        
        try:
            # Test API URL format
            parsed = urlparse(self.exodus_api_url)
            if not parsed.scheme or not parsed.netloc:
                self.logger.error("Invalid Exodus API URL format")
                return False
        except Exception:
            self.logger.error("Invalid Exodus API URL")
            return False
        
        return True