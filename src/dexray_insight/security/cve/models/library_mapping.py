#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Name Mapping for CVE Scanning

This module handles mapping between library names as detected by dexray-insight
and the names used in CVE databases. Different CVE sources may use different
naming conventions.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set
import re


@dataclass
class LibraryMapping:
    """Maps detected library names to CVE database names"""
    detected_name: str
    cve_names: Dict[str, str]  # CVE source -> name in that source
    ecosystem: Optional[str] = None  # Maven, npm, PyPI, etc.
    aliases: List[str] = None  # Alternative names
    
    def __post_init__(self):
        if self.aliases is None:
            self.aliases = []


class LibraryNameMapper:
    """Handles mapping between detected library names and CVE database names"""
    
    def __init__(self):
        # Initialize with common Android library mappings
        self.mappings = self._initialize_default_mappings()
        self.ecosystem_patterns = self._initialize_ecosystem_patterns()
    
    def _initialize_default_mappings(self) -> Dict[str, LibraryMapping]:
        """Initialize with known mappings for common Android libraries"""
        mappings = {}
        
        # Common Android libraries
        common_mappings = [
            # Google/Android libraries
            LibraryMapping(
                "Google Play Services",
                {"osv": "com.google.android.gms:play-services", "nvd": "google_play_services"},
                "Maven",
                ["play-services", "gms"]
            ),
            LibraryMapping(
                "Firebase",
                {"osv": "com.google.firebase:firebase-core", "nvd": "firebase"},
                "Maven",
                ["firebase-core", "firebase-analytics"]
            ),
            LibraryMapping(
                "AndroidX",
                {"osv": "androidx.core:core", "nvd": "androidx"},
                "Maven",
                ["androidx-core", "android-support"]
            ),
            
            # Networking libraries
            LibraryMapping(
                "OkHttp",
                {"osv": "com.squareup.okhttp3:okhttp", "nvd": "okhttp"},
                "Maven",
                ["okhttp3", "square-okhttp"]
            ),
            LibraryMapping(
                "Retrofit",
                {"osv": "com.squareup.retrofit2:retrofit", "nvd": "retrofit"},
                "Maven",
                ["retrofit2", "square-retrofit"]
            ),
            
            # Image loading libraries
            LibraryMapping(
                "Glide",
                {"osv": "com.github.bumptech.glide:glide", "nvd": "glide"},
                "Maven",
                ["bumptech-glide"]
            ),
            LibraryMapping(
                "Picasso",
                {"osv": "com.squareup.picasso:picasso", "nvd": "picasso"},
                "Maven",
                ["square-picasso"]
            ),
            LibraryMapping(
                "Fresco",
                {"osv": "com.facebook.fresco:fresco", "nvd": "fresco"},
                "Maven",
                ["facebook-fresco"]
            ),
            
            # JSON libraries
            LibraryMapping(
                "Gson",
                {"osv": "com.google.code.gson:gson", "nvd": "gson"},
                "Maven",
                ["google-gson"]
            ),
            LibraryMapping(
                "Jackson",
                {"osv": "com.fasterxml.jackson.core:jackson-core", "nvd": "jackson"},
                "Maven",
                ["jackson-core", "fasterxml-jackson"]
            ),
            
            # Logging libraries
            LibraryMapping(
                "Timber",
                {"osv": "com.jakewharton.timber:timber", "nvd": "timber"},
                "Maven",
                ["jakewharton-timber"]
            ),
            
            # Dependency injection
            LibraryMapping(
                "Dagger",
                {"osv": "com.google.dagger:dagger", "nvd": "dagger"},
                "Maven",
                ["google-dagger"]
            ),
            
            # Database libraries
            LibraryMapping(
                "Room",
                {"osv": "androidx.room:room-runtime", "nvd": "room"},
                "Maven",
                ["androidx-room", "android-room"]
            ),
            LibraryMapping(
                "Realm",
                {"osv": "io.realm:realm-android", "nvd": "realm"},
                "Maven",
                ["realm-android"]
            ),
            
            # Testing libraries
            LibraryMapping(
                "JUnit",
                {"osv": "junit:junit", "nvd": "junit"},
                "Maven",
                ["junit4"]
            ),
            
            # Apache Commons (common vulnerabilities)
            LibraryMapping(
                "Apache Commons Collections",
                {"osv": "org.apache.commons:commons-collections4", "nvd": "commons_collections"},
                "Maven",
                ["commons-collections", "apache-commons-collections"]
            ),
            LibraryMapping(
                "Apache Commons Lang",
                {"osv": "org.apache.commons:commons-lang3", "nvd": "commons_lang"},
                "Maven",
                ["commons-lang", "apache-commons-lang"]
            ),
        ]
        
        # Convert to dictionary keyed by detected name (normalized)
        for mapping in common_mappings:
            key = self._normalize_name(mapping.detected_name)
            mappings[key] = mapping
            
            # Also add aliases as keys
            for alias in mapping.aliases:
                alias_key = self._normalize_name(alias)
                mappings[alias_key] = mapping
        
        return mappings
    
    def _initialize_ecosystem_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns to detect library ecosystems"""
        return {
            "Maven": [
                r"^com\.",
                r"^org\.",
                r"^net\.",
                r"^io\.",
                r"^androidx\.",
                r"^android\."
            ],
            "npm": [
                r"^@",  # Scoped packages
                r"[a-z\-]+$"  # Simple lowercase with hyphens
            ],
            "PyPI": [
                r"[a-z\-_]+$"  # Lowercase with hyphens/underscores
            ]
        }
    
    def get_cve_names(self, detected_name: str, version: Optional[str] = None) -> Dict[str, str]:
        """Get CVE database names for a detected library name"""
        normalized = self._normalize_name(detected_name)
        
        if normalized in self.mappings:
            return self.mappings[normalized].cve_names.copy()
        
        # If no exact mapping found, try to generate reasonable names
        return self._generate_cve_names(detected_name)
    
    def get_ecosystem(self, detected_name: str) -> Optional[str]:
        """Determine the ecosystem for a library"""
        normalized = self._normalize_name(detected_name)
        
        if normalized in self.mappings:
            return self.mappings[normalized].ecosystem
        
        # Try to infer ecosystem from name patterns
        for ecosystem, patterns in self.ecosystem_patterns.items():
            for pattern in patterns:
                if re.match(pattern, detected_name, re.IGNORECASE):
                    return ecosystem
        
        return "Maven"  # Default to Maven for Android libraries
    
    def _generate_cve_names(self, detected_name: str) -> Dict[str, str]:
        """Generate reasonable CVE names when no mapping exists"""
        # Simple approach: use the detected name for all sources
        # In practice, you might want more sophisticated name transformation
        normalized = self._normalize_name(detected_name)
        
        return {
            "osv": detected_name,
            "nvd": normalized,
            "github": detected_name
        }
    
    def _normalize_name(self, name: str) -> str:
        """Normalize library name for consistent lookup"""
        return name.lower().replace("-", "_").replace(".", "_").replace(" ", "_")
    
    def add_mapping(self, mapping: LibraryMapping):
        """Add a new library mapping"""
        key = self._normalize_name(mapping.detected_name)
        self.mappings[key] = mapping
        
        # Also add aliases
        for alias in mapping.aliases:
            alias_key = self._normalize_name(alias)
            self.mappings[alias_key] = mapping
    
    def get_all_known_libraries(self) -> Set[str]:
        """Get all known library names"""
        known = set()
        for mapping in self.mappings.values():
            known.add(mapping.detected_name)
            known.update(mapping.aliases)
        return known