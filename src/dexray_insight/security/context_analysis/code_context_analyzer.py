#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
from typing import Dict, Any

from .models.context_models import CodeContext, CodeLocation, ProtectionLevel


class CodeContextAnalyzer:
    """
    Analyzer for extracting and analyzing code context around detected secrets.
    
    This analyzer examines the surrounding code environment where secrets are
    detected to provide contextual intelligence for better false positive
    detection and risk assessment. It analyzes:
    
    - File paths and types (source, test, configuration, etc.)
    - Surrounding code lines and patterns
    - Variable names, method signatures, and class names
    - Import statements and package declarations
    - Protection mechanisms (encryption, obfuscation, secure storage)
    - Usage patterns and access methods
    
    The analyzer works with multiple sources of information including string
    analysis results, behavior analysis data, and file system information.
    
    Design Pattern: Analyzer Pattern (focused analysis responsibility)
    SOLID Principles: Single Responsibility (code context analysis only)
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # File type patterns for location classification
        self.file_type_patterns = {
            CodeLocation.SOURCE_CODE: [
                r'\.java$', r'\.kt$', r'\.scala$', r'\.groovy$'
            ],
            CodeLocation.TEST_CODE: [
                r'/test/', r'/tests/', r'/androidTest/', r'/unitTest/',
                r'Test\.java$', r'Tests\.java$', r'TestCase\.java$',
                r'Mock\w+\.java$', r'Fake\w+\.java$', r'Stub\w+\.java$'
            ],
            CodeLocation.RESOURCE_FILE: [
                r'\.xml$', r'/res/', r'/assets/',
                r'strings\.xml$', r'colors\.xml$', r'styles\.xml$'
            ],
            CodeLocation.CONFIGURATION_FILE: [
                r'\.properties$', r'\.json$', r'\.yml$', r'\.yaml$',
                r'config\.' r'\.conf$', r'\.ini$', r'\.cfg$'
            ],
            CodeLocation.BUILD_SCRIPT: [
                r'build\.gradle$', r'settings\.gradle$', r'\.gradle$',
                r'pom\.xml$', r'build\.xml$', r'Makefile$',
                r'gradle\.properties$', r'proguard.*\.pro$'
            ]
        }
        
        # Protection mechanism indicators
        self.protection_indicators = {
            ProtectionLevel.ENCRYPTION: [
                r'\bcipher\b', r'\bencrypt\b', r'\bdecrypt\b', r'\baes\b', r'\brsa\b',
                r'\bkeystore\b', r'\bandroidkeystore\b', r'\bsecretkey\b',
                r'javax\.crypto', r'java\.security', r'\.doFinal\b'
            ],
            ProtectionLevel.OBFUSCATION: [
                r'\bbase64\b', r'\.decode\b', r'\.encode\b', r'\bobfuscat\b',
                r'\bdeobfuscat\b', r'\bencode\b', r'\bxor\b'
            ],
            ProtectionLevel.ENVIRONMENT: [
                r'System\.getenv\b', r'System\.getProperty\b', r'\bgetenv\b',
                r'Environment\.', r'ProcessBuilder'
            ],
            ProtectionLevel.BUILD_TIME_INJECTION: [
                r'BuildConfig\.', r'@Value\b', r'\$\{.*\}', r'gradle\.properties'
            ],
            ProtectionLevel.SECURE_STORAGE: [
                r'SharedPreferences', r'EncryptedSharedPreferences', 
                r'KeyStore\.getInstance', r'SecureRandom', r'KeyGenerator'
            ]
        }
        
        # Context keywords for variable/method analysis
        self.security_keywords = {
            'secret_related': ['secret', 'key', 'token', 'auth', 'credential', 'password'],
            'crypto_related': ['encrypt', 'decrypt', 'cipher', 'hash', 'sign', 'verify'],
            'storage_related': ['store', 'save', 'persist', 'cache', 'preference'],
            'network_related': ['http', 'api', 'client', 'request', 'response', 'url']
        }
    
    def analyze_string_context(self, finding: Dict[str, Any], 
                              analysis_results: Dict[str, Any]) -> CodeContext:
        """
        Analyze the code context for a detected string/secret.
        
        Args:
            finding: The security finding containing location and value information
            analysis_results: Complete analysis results from all modules
            
        Returns:
            CodeContext with extracted contextual information
        """
        context = CodeContext()
        
        # Extract basic location information
        self._extract_basic_location_info(finding, context)
        
        # Analyze file path and determine location type
        if context.file_path:
            context.location_type = self._determine_location_type(context.file_path)
        
        # Extract surrounding context from string analysis
        string_analysis = analysis_results.get('string_analysis', {})
        if string_analysis:
            self._extract_surrounding_context_from_strings(finding.get('value', ''), 
                                                         string_analysis, context)
        
        # Detect protection mechanisms
        context.protection_level = self._detect_protection_level(context)
        
        # Enhance with behavior analysis if available
        behavior_analysis = analysis_results.get('behaviour_analysis', {})
        if behavior_analysis:
            context = self._enhance_context_with_behavior_analysis(context, behavior_analysis)
        
        self.logger.debug(f"Analyzed context for {finding.get('type', 'unknown')}: "
                         f"{context.location_type.value}, protection: {context.protection_level.value}")
        
        return context
    
    def _extract_basic_location_info(self, finding: Dict[str, Any], context: CodeContext):
        """Extract basic location information from the finding."""
        context.file_path = finding.get('file_path')
        context.line_number = finding.get('line_number')
        
        # Parse location string for additional context
        location = finding.get('location', '')
        if 'xml' in location.lower():
            context.location_type = CodeLocation.RESOURCE_FILE
        elif 'test' in location.lower():
            context.location_type = CodeLocation.TEST_CODE
        elif 'smali' in location.lower() or 'dex' in location.lower():
            context.location_type = CodeLocation.SOURCE_CODE
    
    def _determine_location_type(self, file_path: str) -> CodeLocation:
        """
        Determine the location type based on file path patterns.
        
        Args:
            file_path: The file path to analyze
            
        Returns:
            CodeLocation enum value
        """
        if not file_path:
            return CodeLocation.UNKNOWN
        
        file_path_lower = file_path.lower()
        
        # Check in priority order (most specific first)
        # Order matters: check more specific patterns before generic ones
        priority_order = [
            CodeLocation.TEST_CODE,
            CodeLocation.BUILD_SCRIPT,
            CodeLocation.CONFIGURATION_FILE,
            CodeLocation.RESOURCE_FILE,
            CodeLocation.SOURCE_CODE  # Most generic, check last
        ]
        
        for location_type in priority_order:
            if location_type in self.file_type_patterns:
                patterns = self.file_type_patterns[location_type]
                for pattern in patterns:
                    if re.search(pattern, file_path_lower):
                        return location_type
        
        return CodeLocation.UNKNOWN
    
    def _extract_surrounding_context_from_strings(self, target_string: str,
                                                string_data: Dict[str, Any],
                                                context: CodeContext = None) -> CodeContext:
        """
        Extract surrounding context by analyzing related strings from string analysis.
        
        Args:
            target_string: The target string/secret to find context for
            string_data: String analysis results
            context: Existing context to enhance (or None to create new)
            
        Returns:
            CodeContext with surrounding context information
        """
        if context is None:
            context = CodeContext()
        
        # Handle both dict and object types for string_data
        if hasattr(string_data, 'to_dict'):
            string_dict = string_data.to_dict()
        elif isinstance(string_data, dict):
            string_dict = string_data
        else:
            return context
        
        all_strings = string_dict.get('all_strings', [])
        if not all_strings:
            # Fallback: collect strings from other fields
            all_strings = []
            for key in ['emails', 'urls', 'domains', 'ip_addresses']:
                strings = string_dict.get(key, [])
                if isinstance(strings, list):
                    all_strings.extend(strings)
        
        # Find strings that contain or are related to our target string
        related_strings = []
        target_lower = target_string.lower()
        
        for string_val in all_strings:
            if not isinstance(string_val, str):
                continue
            
            string_lower = string_val.lower()
            
            # Direct containment check
            if target_lower in string_lower or string_lower in target_lower:
                related_strings.append(string_val)
                continue
            
            # Check for code patterns that might reference our target
            # Look for variable assignments, method calls, etc.
            if any(keyword in string_lower for keyword in ['string ', 'final ', 'static ', '=', '(', ')']):
                if any(keyword in string_lower for keyword in ['key', 'token', 'secret', 'api', 'auth']):
                    related_strings.append(string_val)
        
        # Analyze related strings for context
        for related_string in related_strings[:20]:  # Limit to avoid performance issues
            self._parse_java_like_code(related_string, context)
        
        return context
    
    def _parse_java_like_code(self, code_line: str, context: CodeContext) -> CodeContext:
        """
        Parse a line of Java-like code to extract context information.
        
        Args:
            code_line: The code line to parse
            context: The context object to populate
            
        Returns:
            Updated CodeContext
        """
        code_line = code_line.strip()
        if not code_line:
            return context
        
        # Add to surrounding lines
        if code_line not in context.surrounding_lines and len(context.surrounding_lines) < 10:
            context.surrounding_lines.append(code_line)
        
        # Parse different types of Java constructs
        
        # 1. Package declarations
        package_match = re.match(r'package\s+([\w.]+)\s*;', code_line)
        if package_match:
            context.package_names.add(package_match.group(1))
            return context
        
        # 2. Import statements
        import_match = re.match(r'import\s+(?:static\s+)?([\w.*]+)\s*;', code_line)
        if import_match:
            import_name = import_match.group(1)
            context.imports.add(import_name)
            # Extract class name from import
            if '.' in import_name and not import_name.endswith('*'):
                class_name = import_name.split('.')[-1]
                context.class_names.add(class_name)
            return context
        
        # 3. Annotations
        if code_line.startswith('@'):
            context.annotations.append(code_line)
            return context
        
        # 4. Comments (single-line and multi-line)
        if (code_line.startswith('//') or code_line.startswith('/*') or 
            code_line.startswith('*') or code_line.endswith('*/')):
            context.comments.append(code_line)
            return context
        
        # 5. Class declarations
        class_match = re.search(r'\b(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+[\w\s,]+)?\s*\{?', code_line)
        if class_match:
            context.class_names.add(class_match.group(1))
            if class_match.group(2):  # extends clause
                context.class_names.add(class_match.group(2))
            return context
        
        # 6. Method declarations/calls
        method_match = re.search(r'(\w+)\s*\([^)]*\)', code_line)
        if method_match:
            method_match.group(1)
            # Full method signature
            method_sig = method_match.group(0)
            if method_sig not in context.method_signatures and len(context.method_signatures) < 20:
                context.method_signatures.append(method_sig)
        
        # 7. Variable declarations and assignments
        # Look for patterns like: Type varName = value; or String API_KEY = "...";
        var_patterns = [
            r'\b(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(\w+)\s+(\w+)\s*=',
            r'\b(\w+)\s*=\s*',
            r'\.(\w+)\s*\(',  # Method calls like obj.method()
            r'\.(\w+)\b',     # Field access like obj.field
        ]
        
        for pattern in var_patterns:
            matches = re.findall(pattern, code_line)
            for match in matches:
                if isinstance(match, tuple):
                    # Variable declaration: (Type, varName)
                    if len(match) == 2:
                        context.class_names.add(match[0])  # Type
                        context.variable_names.add(match[1])  # Variable name
                    elif len(match) == 1:
                        context.variable_names.add(match[0])
                else:
                    # Single capture group
                    context.variable_names.add(match)
        
        # 8. String literals and constants
        string_literals = re.findall(r'"([^"]+)"', code_line)
        for literal in string_literals:
            # If the literal contains security-related keywords, track it
            if any(keyword in literal.lower() for keyword in self.security_keywords['secret_related']):
                context.variable_names.add(literal[:30])  # Truncate long literals
        
        # 9. BuildConfig usage (indicates build-time injection)
        if 'BuildConfig.' in code_line:
            context.class_names.add('BuildConfig')
            buildconfig_match = re.search(r'BuildConfig\.(\w+)', code_line)
            if buildconfig_match:
                context.variable_names.add(buildconfig_match.group(1))
                context.protection_level = ProtectionLevel.BUILD_TIME_INJECTION
        
        return context
    
    def _detect_protection_level(self, context: CodeContext) -> ProtectionLevel:
        """
        Detect the protection level based on context analysis.
        
        Args:
            context: The code context to analyze
            
        Returns:
            ProtectionLevel indicating how the secret is protected
        """
        # Check all context elements for protection indicators
        all_text = []
        all_text.extend(context.surrounding_lines)
        all_text.extend(context.method_signatures)
        all_text.extend([str(imp) for imp in context.imports])
        all_text.extend([str(cls) for cls in context.class_names])
        all_text.extend([str(var) for var in context.variable_names])
        
        combined_text = ' '.join(all_text).lower()
        
        # Check each protection level (in order of preference/security)
        for protection_level, indicators in self.protection_indicators.items():
            for indicator in indicators:
                if re.search(indicator, combined_text, re.IGNORECASE):
                    return protection_level
        
        # Special case: Check for specific patterns that indicate protection
        
        # Environment variables
        if any(re.search(r'\bsystem\.getenv\b|\bgetenv\b|\benvironment\b', text, re.IGNORECASE) 
               for text in all_text):
            return ProtectionLevel.ENVIRONMENT
        
        # Build-time injection
        if any(re.search(r'\bbuildconfig\b|\$\{.*\}|@value\b', text, re.IGNORECASE) 
               for text in all_text):
            return ProtectionLevel.BUILD_TIME_INJECTION
        
        # Runtime injection (less common but possible)
        if any(re.search(r'\bgetstring\b.*\br\.string\b|\bgetresources\b', text, re.IGNORECASE) 
               for text in all_text):
            return ProtectionLevel.RUNTIME_INJECTION
        
        # No protection detected
        return ProtectionLevel.NONE
    
    def _enhance_context_with_behavior_analysis(self, context: CodeContext, 
                                               behavior_analysis: Dict[str, Any]) -> CodeContext:
        """
        Enhance context with information from behavior analysis.
        
        Args:
            context: Existing code context
            behavior_analysis: Behavior analysis results
            
        Returns:
            Enhanced CodeContext
        """
        # Check if we have androguard objects for deep analysis
        androguard_objects = behavior_analysis.get('androguard_objects', {})
        
        if androguard_objects.get('mode') == 'deep':
            # Deep analysis mode - can extract more detailed context
            self.logger.debug("Enhancing context with deep behavior analysis")
            
            # Additional context extraction could be done here with androguard objects
            # For now, we maintain the existing context structure
            pass
        else:
            # Fast analysis mode - limited enhancement
            self.logger.debug("Limited context enhancement in fast analysis mode")
        
        return context