#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Domain Filter for String Analysis

Specialized filter for extracting and validating domain names from string collections.
Implements comprehensive false positive filtering for mobile app analysis.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import re
import logging
from typing import List, Set, Dict


class DomainFilter:
    """
    Specialized filter for domain name extraction and validation.
    
    Single Responsibility: Extract valid domain names from strings with
    comprehensive false positive filtering for mobile app analysis.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Domain pattern matching
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        
        # Comprehensive invalid patterns for mobile app analysis
        self._initialize_invalid_patterns()
    
    def _initialize_invalid_patterns(self):
        """Initialize comprehensive invalid patterns for false positive filtering"""
        
        # File extensions that commonly appear as false positives
        self.invalid_extensions = (
            # Programming language files
            ".java", ".kt", ".class", ".js", ".ts", ".py", ".rb", ".cpp", ".c", ".h", ".hpp",
            ".cs", ".vb", ".swift", ".go", ".rs", ".scala", ".clj", ".hs", ".ml", ".php",
            
            # Data and markup files
            ".xml", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
            ".html", ".htm", ".css", ".scss", ".less", ".md", ".txt", ".csv", ".tsv",
            
            # RDF and semantic web formats
            ".ttl", ".rdf", ".owl", ".n3", ".nt", ".trig", ".jsonld",
            
            # Archive and binary files
            ".zip", ".jar", ".aar", ".tar", ".gz", ".7z", ".rar", ".dex", ".so", ".dll",
            ".exe", ".bin", ".dat", ".db", ".sqlite", ".realm",
            
            # Image and media files
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".mp4", ".avi",
            
            # Build and config files
            ".gradle", ".maven", ".pom", ".lock", ".log", ".tmp", ".cache", ".bak",
            ".rc", ".sig", ".keystore", ".jks", ".p12", ".pem", ".crt", ".key",
            
            # Documentation and misc
            ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx"
        )
        
        # Package/namespace prefixes that commonly appear as false positives
        self.invalid_prefixes = (
            # Android and Google
            "android.", "androidx.", "com.android.", "com.google.", "com.google.android.",
            "google.", "gms.", "firebase.", "play.google.", "android.support.",
            
            # Java and JVM ecosystem
            "java.", "javax.", "org.apache.", "org.springframework.", "org.hibernate.",
            "org.junit.", "org.slf4j.", "org.w3c.", "org.xml.", "org.json.",
            
            # .NET and Microsoft
            "microsoft.", "system.", "windows.", "xamarin.", "mono.", "dotnet.",
            "mscorlib.", "netstandard.", "aspnet.", "entityframework.",
            
            # Mobile development frameworks
            "cordova.", "phonegap.", "react.native.", "flutter.", "ionic.", "xamarin.android.",
            "titanium.", "sencha.", "ext.", "appcelerator.",
            
            # Development tools and libraries
            "jetbrains.", "intellij.", "eclipse.", "gradle.", "maven.", "sbt.", "ant.",
            "junit.", "mockito.", "retrofit.", "okhttp.", "gson.", "jackson.",
            
            # Common libraries and frameworks
            "apache.", "commons.", "spring.", "hibernate.", "log4j.", "slf4j.",
            "guice.", "dagger.", "butterknife.", "picasso.", "glide.", "fresco.",
            
            # Version control and build systems
            "git.", "svn.", "mercurial.", "bzr.", "jenkins.", "travis.", "circle.",
            
            # Development artifacts
            "debug.", "test.", "mock.", "stub.", "temp.", "tmp.", "cache.", "build.",
            "target.", "bin.", "obj.", "out.", "dist.", "lib.", "libs.", "assets.",
            
            # Protocol and service prefixes
            "http.", "https.", "ftp.", "ssh.", "tcp.", "udp.", "smtp.", "pop3.", "imap.",
            
            # File system and OS
            "file.", "directory.", "folder.", "path.", "unix.", "linux.", "windows.",
            "macos.", "ios.", "darwin.",
            
            # Network and infrastructure
            "localhost.", "127.0.0.1.", "0.0.0.0.", "192.168.", "10.0.", "172.",
            
            # Common false positive patterns
            "interface.", "class.", "struct.", "enum.", "const.", "static.", "final.",
            "abstract.", "public.", "private.", "protected.", "internal.",
            
            # Specific problematic patterns from APK analysis
            "ueventd.", "truststore.", "mraid.", "multidex.", "proguard.", "r8.",
            "dex2jar.", "baksmali.", "smali.", "jadx.", "apktool.",
            
            # Database and ORM
            "sqlite.", "realm.", "room.", "greenDAO.", "dbflow.", "ormlite.",
            
            # Analytics and crash reporting
            "crashlytics.", "fabric.", "flurry.", "mixpanel.", "amplitude.",
            "bugsnag.", "sentry.", "appsee.", "uxcam.",
            
            # Ad networks (common false positives)
            "admob.", "adsense.", "doubleclick.", "unity3d.ads.", "chartboost.",
            "vungle.", "applovin.", "ironsource.", "tapjoy."
        )
        
        # Complex regex patterns for advanced false positive detection
        self.invalid_regex_patterns = [
            # File extensions (regex patterns for flexibility)
            r"\.(java|kt|class|js|ts|py|rb|cpp|c|h|hpp|cs|vb|swift|go|rs|scala|clj|hs|ml|php)$",
            r"\.(xml|json|yaml|yml|toml|ini|cfg|conf|properties)$",
            r"\.(ttl|rdf|owl|n3|nt|trig|jsonld)$",  # RDF/semantic web formats
            r"\.(html|htm|css|scss|less|md|txt|csv|tsv)$",
            r"\.(zip|jar|aar|tar|gz|7z|rar|dex|so|dll|exe|bin|dat|db|sqlite|realm)$",
            r"\.(png|jpg|jpeg|gif|svg|ico|webp|mp4|avi)$",
            r"\.(gradle|maven|pom|lock|log|tmp|cache|bak)$",
            r"\.(rc|sig|keystore|jks|p12|pem|crt|key)$",
            
            # Development and framework patterns
            r"^\w+\.gms\b", r"videoApi\.set", r"line\.separator", r"multidex\.version",
            r"androidx\.multidex", r"dd\.MM\.yyyy", r"document\.hidelocation",
            r"angtrim\.com\.fivestarslibrary", r"^Theme\b", r"betcheg\.mlgphotomontag",
            r"MultiDex\.lock", r"\.ConsoleError$", r"^\w+\.android\b",
            
            # Package and class patterns
            r"^[A-Z]\w*\.[A-Z]\w*$",  # Likely class references (e.g., "Utils.Logger")
            r"^\w+\$\w+",  # Inner class references (e.g., "Activity$1")
            r"\.R\.\w+$",  # Android resource references
            r"\.BuildConfig$",  # Build configuration references
            
            # Version and build patterns
            r"\.v\d+$", r"\.version\d*$", r"\.build\d*$", r"\.snapshot$",
            r"\.alpha\d*$", r"\.beta\d*$", r"\.rc\d*$", r"\.final$",
            
            # Configuration and property patterns
            r"\.debug$", r"\.release$", r"\.prod$", r"\.dev$", r"\.test$",
            r"\.staging$", r"\.local$", r"\.config$", r"\.settings$",
            
            # Network and protocol patterns
            r"^(localhost|127\.0\.0\.1|0\.0\.0\.0)$",
            r"^192\.168\.", r"^10\.0\.", r"^172\.(1[6-9]|2[0-9]|3[01])\.",  # Private IP ranges
            
            # File system patterns
            r"^[A-Z]:\\", r"^\/[a-z]+\/", r"\.\.\/", r"\.\/",  # File paths
            
            # Common false positive strings
            r"^(NULL|null|undefined|true|false|yes|no|on|off)$",
            r"^(error|warning|info|debug|trace|log)$",
            r"^(start|stop|pause|resume|init|destroy|create|delete)$",
            
            # Database and SQL patterns
            r"\.sql$", r"\.db$", r"\.sqlite$", r"^(select|insert|update|delete|create|drop|alter)\.",
            
            # Obfuscated or minified patterns
            r"^[a-z]$",  # Single letter domains (likely obfuscated)
            r"^[a-z]{1,2}\.[a-z]{1,2}$",  # Very short domain-like strings
            
            # Specific mobile development patterns
            r"\.aar$", r"\.apk$", r"\.aab$", r"\.ipa$",  # Mobile app package files
            r"cordova\.", r"phonegap\.", r"ionic\.", r"nativescript\.",
            r"flutter\.", r"xamarin\.", r"reactnative\.", r"titanium\.",
            
            # Analytics and tracking patterns (common false positives)
            r"analytics\.", r"tracking\.", r"metrics\.", r"telemetry\.",
            r"crashlytics\.", r"firebase\.", r"amplitude\.", r"mixpanel\.",
            
            # Ad network patterns (common false positives)
            r"ads\.", r"adnw\.", r"adsystem\.", r"advertising\.",
            r"admob\.", r"doubleclick\.", r"googlesyndication\."
        ]
    
    def filter_domains(self, strings: Set[str]) -> List[str]:
        """
        Filter and validate domain names from string collection.
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of valid domain names
        """
        potential_domains = []
        
        # First pass: basic pattern matching
        for string in strings:
            if self.domain_pattern.match(string):
                potential_domains.append(string)
        
        self.logger.debug(f"Found {len(potential_domains)} potential domains from pattern matching")
        
        # Second pass: comprehensive validation
        validated_domains = []
        for domain in potential_domains:
            if self._is_valid_domain(domain):
                validated_domains.append(domain)
                self.logger.debug(f"Valid domain found: {domain}")
        
        self.logger.info(f"Extracted {len(validated_domains)} valid domains after filtering")
        return validated_domains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate if a string is a valid domain with comprehensive false positive filtering.
        
        This method implements extensive filtering to reduce false positives from:
        - Source code files and development artifacts
        - Package names and class paths
        - Configuration files and build artifacts
        - Version identifiers and development metadata
        
        Args:
            domain: String to validate as domain
            
        Returns:
            True if string is a valid domain name
        """
        # Basic validation checks
        if " " in domain or len(domain.strip()) != len(domain):
            return False
        
        # Check if the string ends with uppercase letters (likely class names)
        if domain[-1].isupper():
            return False
        
        # Enhanced file extension filtering
        if domain.lower().endswith(self.invalid_extensions):
            return False
        
        # Enhanced package/namespace prefixes filtering
        domain_lower = domain.lower()
        if any(domain_lower.startswith(prefix) for prefix in self.invalid_prefixes):
            return False
        
        # Enhanced invalid character detection
        if re.search(r"[<>:{}\[\]@!#$%^&*()+=,;\"\\|`~]", domain):
            return False
        
        # Version pattern detection (e.g., "1.2.3", "v1.0.0", "2021.1.1")
        if re.search(r"^v?\d+\.\d+(\.\d+)*([a-z]+\d*)?$", domain, re.IGNORECASE):
            return False
        
        # Build identifier patterns (e.g., "build.123", "version.2.1")
        if re.search(r"^(build|version|release|snapshot|alpha|beta|rc)\.\d+", domain, re.IGNORECASE):
            return False
        
        # Apply complex regex patterns
        for pattern in self.invalid_regex_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return False
        
        # Additional validation: Check if domain has reasonable structure
        parts = domain.split('.')
        if len(parts) < 2:  # Domains should have at least 2 parts
            return False
        
        # Check for reasonable TLD (top-level domain)
        tld = parts[-1].lower()
        if len(tld) < 2 or len(tld) > 6:  # TLD should be reasonable length
            return False
        
        # Check if TLD contains only letters (no numbers in TLD)
        if not tld.isalpha():
            return False
        
        # Check for reasonable subdomain/domain lengths
        for part in parts:
            if len(part) == 0 or len(part) > 63:  # RFC limits
                return False
            if part.startswith('-') or part.endswith('-'):  # Invalid hyphen placement
                return False
        
        # Final check: domain shouldn't be too long overall (RFC 1035 limit)
        if len(domain) > 253:
            return False
        
        return True
    
    def categorize_domains_by_tld(self, domains: List[str]) -> Dict[str, List[str]]:
        """
        Group domains by their top-level domain (TLD).
        
        Args:
            domains: List of domain names
            
        Returns:
            Dictionary mapping TLDs to lists of domains
        """
        categorized = {}
        
        for domain in domains:
            try:
                tld = domain.split('.')[-1].lower()
                if tld not in categorized:
                    categorized[tld] = []
                categorized[tld].append(domain)
            except (IndexError, AttributeError):
                self.logger.warning(f"Could not extract TLD from domain: {domain}")
        
        return categorized
    
    def get_domain_statistics(self, domains: List[str]) -> Dict[str, any]:
        """
        Generate statistics about the extracted domains.
        
        Args:
            domains: List of domain names
            
        Returns:
            Dictionary with domain statistics
        """
        stats = {
            'total_domains': len(domains),
            'unique_tlds': len(set(domain.split('.')[-1].lower() for domain in domains)),
            'average_length': sum(len(domain) for domain in domains) / len(domains) if domains else 0,
            'longest_domain': max(domains, key=len) if domains else None,
            'shortest_domain': min(domains, key=len) if domains else None
        }
        
        # TLD distribution
        tld_counts = {}
        for domain in domains:
            tld = domain.split('.')[-1].lower()
            tld_counts[tld] = tld_counts.get(tld, 0) + 1
        
        stats['tld_distribution'] = dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True))
        
        return stats
    
    def extract_root_domains(self, domains: List[str]) -> List[str]:
        """
        Extract root domains from a list of domains (remove subdomains).
        
        Args:
            domains: List of domain names
            
        Returns:
            List of unique root domains
        """
        root_domains = set()
        
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                # Extract last 2 parts as root domain (e.g., example.com from sub.example.com)
                root_domain = '.'.join(parts[-2:])
                root_domains.add(root_domain)
        
        return sorted(list(root_domains))