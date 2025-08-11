#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Pattern Definitions for Heuristic Detection

This module contains known library patterns used for heuristic-based library detection.
Each pattern defines packages, classes, permissions, and other characteristics that
uniquely identify third-party libraries in Android applications.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
for better maintainability and to follow Single Responsibility Principle.
"""

from dexray_insight.results.LibraryDetectionResults import LibraryCategory

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