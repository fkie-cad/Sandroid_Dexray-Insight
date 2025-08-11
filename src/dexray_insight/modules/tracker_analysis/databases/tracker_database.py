#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Database for Pattern-Based Detection

Static database of known tracking SDK patterns extracted from the original
monolithic tracker_analysis.py module. Contains comprehensive pattern definitions
for advertising, analytics, and tracking SDKs.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
for better maintainability and to follow Single Responsibility Principle.
"""

from typing import Dict, Any


class TrackerDatabase:
    """
    Static database of known tracker patterns for detection.
    
    Single Responsibility: Provide access to tracker pattern definitions
    with metadata for advertising, analytics, and tracking SDKs.
    """
    
    # Comprehensive tracker database with patterns, version patterns, and metadata
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
    
    @classmethod
    def get_tracker_database(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get the complete tracker database.
        
        Returns:
            Dict mapping tracker names to their pattern definitions
        """
        return cls.TRACKER_DATABASE.copy()
    
    @classmethod
    def get_tracker_count(cls) -> int:
        """
        Get the total number of tracked patterns.
        
        Returns:
            Number of tracker patterns in the database
        """
        return len(cls.TRACKER_DATABASE)
    
    @classmethod
    def get_tracker_categories(cls) -> set:
        """
        Get all unique tracker categories.
        
        Returns:
            Set of unique category names
        """
        categories = set()
        for tracker_data in cls.TRACKER_DATABASE.values():
            categories.add(tracker_data.get('category', 'Unknown'))
        return categories
    
    @classmethod
    def get_trackers_by_category(cls, category: str) -> Dict[str, Dict[str, Any]]:
        """
        Get all trackers belonging to a specific category.
        
        Args:
            category: Category name to filter by
            
        Returns:
            Dict of trackers in the specified category
        """
        return {
            name: data for name, data in cls.TRACKER_DATABASE.items()
            if data.get('category', '') == category
        }