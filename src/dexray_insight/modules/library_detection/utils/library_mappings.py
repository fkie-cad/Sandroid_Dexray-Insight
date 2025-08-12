#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Name Mapping System

This module provides mapping between library names found in Android properties files
and their actual Maven Central coordinates, along with additional metadata for
accurate version checking and analysis.
"""

from typing import Dict, Optional, NamedTuple
import re


class LibraryMapping(NamedTuple):
    """
    Library mapping information
    
    Args:
        maven_group_id: Maven Central group ID (e.g., 'com.google.android.gms')
        maven_artifact_id: Maven Central artifact ID (e.g., 'play-services-cast')
        display_name: Human-readable name for display
        category: Library category
        description: Short description of the library
        official_url: Official documentation/homepage URL
    """
    maven_group_id: str
    maven_artifact_id: str
    display_name: str
    category: str = "unknown"
    description: str = ""
    official_url: str = ""


class LibraryMappingRegistry:
    """
    Registry for library name mappings
    
    This class provides mapping between property file names and Maven coordinates
    for accurate version checking and library identification.
    """
    
    def __init__(self):
        """Initialize the library mapping registry"""
        self._mappings: Dict[str, LibraryMapping] = {}
        self._initialize_default_mappings()
    
    def _initialize_default_mappings(self):
        """Initialize default library mappings"""
        
        # Google Play Services Libraries
        play_services_mappings = {
            "play-services-cast": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-cast",
                display_name="Google Play Services Cast",
                category="media",
                description="Google Cast functionality for Android",
                official_url="https://developers.google.com/cast/docs/android_sender"
            ),
            "play-services-auth": LibraryMapping(
                maven_group_id="com.google.android.gms", 
                maven_artifact_id="play-services-auth",
                display_name="Google Play Services Auth",
                category="authentication",
                description="Google authentication services",
                official_url="https://developers.google.com/identity/sign-in/android"
            ),
            "play-services-location": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-location", 
                display_name="Google Play Services Location",
                category="location",
                description="Location and activity recognition APIs",
                official_url="https://developers.google.com/location-context/activity-recognition"
            ),
            "play-services-maps": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-maps",
                display_name="Google Maps Android API",
                category="maps",
                description="Google Maps integration for Android",
                official_url="https://developers.google.com/maps/documentation/android-sdk"
            ),
            "play-services-base": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-base",
                display_name="Google Play Services Base",
                category="core",
                description="Base Google Play Services functionality",
                official_url="https://developers.google.com/android/guides/setup"
            ),
            "play-services-basement": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-basement",
                display_name="Google Play Services Basement",
                category="core",
                description="Core Google Play Services infrastructure",
                official_url="https://developers.google.com/android/guides/setup"
            ),
            "play-services-tasks": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-tasks",
                display_name="Google Play Services Tasks",
                category="core",
                description="Task API for asynchronous operations",
                official_url="https://developers.google.com/android/guides/tasks"
            ),
            "play-services-vision": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-vision",
                display_name="Google Play Services Vision",
                category="ml",
                description="Mobile Vision APIs",
                official_url="https://developers.google.com/vision"
            ),
            "play-services-ads-identifier": LibraryMapping(
                maven_group_id="com.google.android.gms",
                maven_artifact_id="play-services-ads-identifier",
                display_name="Google Play Services Ads Identifier",
                category="advertising",
                description="Advertising ID services",
                official_url="https://support.google.com/googleplay/android-developer/answer/6048248"
            ),
            "play-services-analytics": LibraryMapping(
                maven_group_id="com.google.android.gms", 
                maven_artifact_id="play-services-analytics",
                display_name="Google Analytics for Android",
                category="analytics", 
                description="Google Analytics SDK",
                official_url="https://developers.google.com/analytics/devguides/collection/android/v4"
            )
        }
        
        # Firebase Libraries
        firebase_mappings = {
            "firebase-messaging": LibraryMapping(
                maven_group_id="com.google.firebase",
                maven_artifact_id="firebase-messaging",
                display_name="Firebase Cloud Messaging", 
                category="messaging",
                description="Firebase push notification service",
                official_url="https://firebase.google.com/docs/cloud-messaging"
            ),
            "firebase-common": LibraryMapping(
                maven_group_id="com.google.firebase",
                maven_artifact_id="firebase-common",
                display_name="Firebase Common",
                category="core",
                description="Common Firebase functionality",
                official_url="https://firebase.google.com"
            ),
            "firebase-components": LibraryMapping(
                maven_group_id="com.google.firebase",
                maven_artifact_id="firebase-components",
                display_name="Firebase Components",
                category="core", 
                description="Firebase dependency injection framework",
                official_url="https://firebase.google.com"
            ),
            "firebase-annotations": LibraryMapping(
                maven_group_id="com.google.firebase",
                maven_artifact_id="firebase-annotations",
                display_name="Firebase Annotations",
                category="core",
                description="Firebase annotation library",
                official_url="https://firebase.google.com"
            ),
            "firebase-iid": LibraryMapping(
                maven_group_id="com.google.firebase", 
                maven_artifact_id="firebase-iid",
                display_name="Firebase Instance ID", 
                category="core",
                description="Firebase Instance ID service", 
                official_url="https://firebase.google.com/docs/reference/android/com/google/firebase/iid/package-summary"
            ),
            "firebase-measurement-connector": LibraryMapping(
                maven_group_id="com.google.firebase",
                maven_artifact_id="firebase-measurement-connector",
                display_name="Firebase Measurement Connector",
                category="analytics",
                description="Firebase Analytics measurement connector",
                official_url="https://firebase.google.com/docs/analytics"
            )
        }
        
        # Android/AndroidX Libraries  
        android_mappings = {
            "billing": LibraryMapping(
                maven_group_id="com.android.billingclient",
                maven_artifact_id="billing",
                display_name="Google Play Billing Library",
                category="billing",
                description="Google Play in-app billing",
                official_url="https://developer.android.com/google/play/billing"
            ),
            "app-update": LibraryMapping(
                maven_group_id="com.google.android.play",
                maven_artifact_id="app-update",
                display_name="Google Play App Update",
                category="core",
                description="In-app updates API",
                official_url="https://developer.android.com/guide/playcore/in-app-updates"
            ),
            "review": LibraryMapping(
                maven_group_id="com.google.android.play", 
                maven_artifact_id="review",
                display_name="Google Play In-App Review", 
                category="core",
                description="In-app review API",
                official_url="https://developer.android.com/guide/playcore/in-app-review"
            ),
            "integrity": LibraryMapping(
                maven_group_id="com.google.android.play",
                maven_artifact_id="integrity",
                display_name="Google Play Integrity API",
                category="security",
                description="App integrity verification",
                official_url="https://developer.android.com/google/play/integrity"
            ),
            "core-common": LibraryMapping(
                maven_group_id="androidx.arch.core",
                maven_artifact_id="core-common", 
                display_name="AndroidX Core Common",
                category="core",
                description="AndroidX architecture core components",
                official_url="https://developer.android.com/jetpack/androidx/releases/arch-core"
            )
        }
        
        # Popular Third-party Libraries
        thirdparty_mappings = {
            "gson": LibraryMapping(
                maven_group_id="com.google.code.gson",
                maven_artifact_id="gson",
                display_name="Gson",
                category="serialization",
                description="JSON serialization library by Google",
                official_url="https://github.com/google/gson"
            ),
            "okhttp": LibraryMapping(
                maven_group_id="com.squareup.okhttp3",
                maven_artifact_id="okhttp", 
                display_name="OkHttp",
                category="networking",
                description="HTTP client library by Square",
                official_url="https://square.github.io/okhttp/"
            ),
            "retrofit": LibraryMapping(
                maven_group_id="com.squareup.retrofit2",
                maven_artifact_id="retrofit",
                display_name="Retrofit",
                category="networking", 
                description="Type-safe HTTP client by Square",
                official_url="https://square.github.io/retrofit/"
            ),
            "glide": LibraryMapping(
                maven_group_id="com.github.bumptech.glide",
                maven_artifact_id="glide",
                display_name="Glide",
                category="imaging", 
                description="Image loading and caching library",
                official_url="https://bumptech.github.io/glide/"
            )
        }
        
        # Facebook-specific libraries
        facebook_mappings = {
            "core-facebook": LibraryMapping(
                maven_group_id="com.facebook.android", 
                maven_artifact_id="facebook-core",
                display_name="Facebook SDK Core",
                category="social",
                description="Facebook SDK core functionality", 
                official_url="https://developers.facebook.com/docs/android"
            ),
            "googleid": LibraryMapping(
                maven_group_id="com.google.android.libraries.identity.googleid",
                maven_artifact_id="googleid",
                display_name="Google ID Library",
                category="authentication",
                description="Google Identity services",
                official_url="https://developers.google.com/identity/android-credential-manager"
            )
        }
        
        # Combine all mappings
        all_mappings = {
            **play_services_mappings,
            **firebase_mappings, 
            **android_mappings,
            **thirdparty_mappings,
            **facebook_mappings
        }
        
        self._mappings.update(all_mappings)
    
    def get_mapping(self, property_name: str) -> Optional[LibraryMapping]:
        """
        Get library mapping by property file name
        
        Args:
            property_name: Name from properties file (e.g., 'play-services-cast')
            
        Returns:
            LibraryMapping if found, None otherwise
        """
        # Direct lookup
        if property_name in self._mappings:
            return self._mappings[property_name]
            
        # Try normalized lookup (remove common suffixes/prefixes)
        normalized = self._normalize_name(property_name)
        if normalized in self._mappings:
            return self._mappings[normalized]
            
        return None
    
    def _normalize_name(self, name: str) -> str:
        """
        Normalize library name for better matching
        
        Args:
            name: Original library name
            
        Returns:
            Normalized name
        """
        # Remove common suffixes and prefixes
        name = name.lower()
        name = re.sub(r'^(lib|android-|androidx-)', '', name)
        name = re.sub(r'(-android|-java|-kotlin|-core)?$', '', name)
        
        return name
    
    def search_by_pattern(self, pattern: str) -> Dict[str, LibraryMapping]:
        """
        Search libraries by pattern
        
        Args:
            pattern: Search pattern (regex supported)
            
        Returns:
            Dictionary of matching libraries
        """
        matches = {}
        pattern_re = re.compile(pattern, re.IGNORECASE)
        
        for name, mapping in self._mappings.items():
            if (pattern_re.search(name) or 
                pattern_re.search(mapping.display_name) or
                pattern_re.search(mapping.maven_artifact_id)):
                matches[name] = mapping
                
        return matches
    
    def add_mapping(self, property_name: str, mapping: LibraryMapping):
        """
        Add or update a library mapping
        
        Args:
            property_name: Property file name
            mapping: Library mapping information
        """
        self._mappings[property_name] = mapping
    
    def get_all_mappings(self) -> Dict[str, LibraryMapping]:
        """Get all available mappings"""
        return self._mappings.copy()
    
    def get_maven_coordinates(self, property_name: str) -> Optional[str]:
        """
        Get Maven coordinates for a library
        
        Args:
            property_name: Property file name
            
        Returns:
            Maven coordinates in format "groupId:artifactId" or None
        """
        mapping = self.get_mapping(property_name)
        if mapping:
            return f"{mapping.maven_group_id}:{mapping.maven_artifact_id}"
        return None


# Global registry instance
_registry = LibraryMappingRegistry()


def get_library_mapping(property_name: str) -> Optional[LibraryMapping]:
    """
    Get library mapping by property name
    
    Args:
        property_name: Name from properties file
        
    Returns:
        LibraryMapping if found, None otherwise
    """
    return _registry.get_mapping(property_name)


def get_maven_coordinates(property_name: str) -> Optional[str]:
    """
    Get Maven coordinates for a library
    
    Args:
        property_name: Property file name
        
    Returns:
        Maven coordinates in format "groupId:artifactId" or None
    """
    return _registry.get_maven_coordinates(property_name)


def search_libraries(pattern: str) -> Dict[str, LibraryMapping]:
    """
    Search libraries by pattern
    
    Args:
        pattern: Search pattern
        
    Returns:
        Dictionary of matching libraries
    """
    return _registry.search_by_pattern(pattern)


def add_custom_mapping(property_name: str, mapping: LibraryMapping):
    """
    Add custom library mapping
    
    Args:
        property_name: Property file name
        mapping: Library mapping information
    """
    _registry.add_mapping(property_name, mapping)