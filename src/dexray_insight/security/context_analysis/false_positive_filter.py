#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import math
import logging
from typing import List, Dict, Any
from collections import Counter

from .models.contextual_finding import ContextualFinding, ContextMetadata, ContextConfidence
from .models.context_models import CodeContext, FalsePositiveIndicator


class FalsePositiveFilter:
    """
    Enhanced false positive filter that uses contextual analysis to reduce noise
    in security findings.
    
    This filter addresses the critical issue of high false positive rates (77K+ 
    low-severity findings) by implementing multiple sophisticated filtering 
    techniques including:
    
    - Placeholder value detection
    - Test context identification  
    - Android system string recognition
    - Entropy analysis
    - Context-aware pattern matching
    
    The filter assigns false positive probabilities to findings based on multiple
    indicators and their confidence levels, allowing for nuanced decision making
    rather than binary filtering.
    
    Design Pattern: Strategy Pattern (used within context analysis workflow)
    SOLID Principles: Single Responsibility (focuses only on false positive detection)
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Enhanced placeholder patterns with higher precision
        self.placeholder_patterns = [
            # Explicit placeholder indicators
            r'(?i)\b(your|insert|replace|add|put).*?(key|token|secret|api|auth)',
            r'(?i)\b(test|example|sample|demo|mock|fake|dummy).*?(key|token|secret|api)',
            r'(?i)\b(placeholder|template|default).*?(key|token|secret|value)',
            
            # Common placeholder formats
            r'(?i)^(your_|insert_|replace_|add_)',
            r'(?i)_(here|placeholder|example|test|demo)$',
            r'\b[A-Z_]+_HERE\b',
            r'\bXXXX+\b',
            
            # Development/debug patterns
            r'(?i)\b(debug|dev|development|staging).*?(key|token|secret)',
            r'(?i)\b(local|localhost|127\.0\.0\.1)',
            
            # Repeated character patterns (unlikely to be real secrets)
            r'^(.)\1{8,}$',  # Same character repeated 8+ times
            r'^(abc|123|xyz|test|null|none){2,}$',  # Simple repeated patterns
        ]
        
        # Test context indicators
        self.test_indicators = {
            'file_patterns': [
                r'/test/',
                r'/tests/',
                r'/androidTest/',
                r'/unitTest/',
                r'/test_data/',
                r'Test\.java$',
                r'Tests\.java$',
                r'TestCase\.java$',
                r'Spec\.java$',
                r'Mock\w+\.java$',
                r'Fake\w+\.java$',
                r'Stub\w+\.java$'
            ],
            'class_patterns': [
                r'.*Test$',
                r'.*Tests$',
                r'.*TestCase$',
                r'.*Spec$',
                r'^Mock.*',
                r'^Fake.*',
                r'^Stub.*',
                r'^Test.*'
            ],
            'import_patterns': [
                r'org\.junit\.',
                r'org\.testng\.',
                r'org\.mockito\.',
                r'org\.robolectric\.',
                r'androidx\.test\.',
                r'android\.support\.test\.',
                r'com\.google\.truth\.',
                r'org\.hamcrest\.'
            ]
        }
        
        # Android system string patterns (very high confidence false positives)
        self.android_system_patterns = [
            # Dalvik/ART class names
            r'^L[a-z]+(/[a-zA-Z_$][a-zA-Z0-9_$]*)*;?$',
            r'^Landroid/',
            r'^Ljava/',
            r'^Ljavax/',
            r'^Landroidx/',
            r'^Lcom/android/',
            
            # Android package names
            r'^android\.',
            r'^androidx\.',
            r'^com\.android\.',
            r'^com\.google\.android\.',
            
            # Common Android method/field names - more comprehensive
            r'^(get|set|on)[A-Z][a-zA-Z]+$',
            r'^(create|destroy|start|stop|pause|resume)[A-Z][a-zA-Z]*$',
            r'(Activity|Service|Receiver|Provider|Fragment|View|Layout)$',
            
            # Android resource identifiers
            r'^@[a-z]+/',
            r'R\.[a-z]+\.[a-zA-Z_][a-zA-Z0-9_]*$',
            
            # Android permissions
            r'^android\.permission\.',
            
            # System properties
            r'^(ro|sys|persist|debug|dalvik|art)\.',
        ]
        
        # Additional Android system keywords for broader matching
        self.android_system_keywords = [
            'findViewById', 'setContentView', 'getSystemService', 'startActivity',
            'bindService', 'registerReceiver', 'onCreateView', 'onResume', 'onPause',
            'getSupportActionBar', 'getActionBar', 'getMenuInflater', 'getLayoutInflater',
            'getSupportFragmentManager', 'getFragmentManager', 'runOnUiThread'
        ]
        
        # Entropy thresholds for different secret types
        self.entropy_thresholds = {
            'base64': 4.0,
            'hex': 3.5,  # Lower threshold for hex strings
            'api_key': 4.5,
            'uuid': 3.8,
            'general': 4.0
        }
    
    def is_placeholder_value(self, value: str) -> bool:
        """
        Determine if a string value appears to be a placeholder.
        
        Args:
            value: The string value to check
            
        Returns:
            True if the value appears to be a placeholder, False otherwise
        """
        if not value or len(value) < 3:
            return False
        
        value_lower = value.lower()
        
        # Check against placeholder patterns
        for pattern in self.placeholder_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        # Additional heuristic checks
        # Check for common placeholder phrases
        placeholder_phrases = [
            'your_api_key', 'insert_key_here', 'api_key_here', 'your_token',
            'replace_me', 'change_me', 'your_secret', 'add_your_key',
            'example_key', 'sample_token', 'test_api_key', 'demo_secret',
            'dummy_key', 'fake_token', 'mock_secret', 'placeholder_key'
        ]
        
        for phrase in placeholder_phrases:
            if phrase in value_lower:
                return True
        
        # Check for placeholder-like patterns
        # All uppercase with underscores (configuration style placeholders)
        if re.match(r'^[A-Z_][A-Z0-9_]*[A-Z_]$', value) and len(value) > 10:
            if any(indicator in value_lower for indicator in ['key', 'token', 'secret', 'api', 'your', 'here']):
                return True
        
        return False
    
    def is_android_system_string(self, value: str) -> bool:
        """
        Determine if a string appears to be an Android system string.
        
        Args:
            value: The string value to check
            
        Returns:
            True if the value appears to be an Android system string, False otherwise
        """
        if not value:
            return False
        
        # Check exact matches against Android system keywords
        if value in self.android_system_keywords:
            return True
        
        # Check against Android system patterns
        for pattern in self.android_system_patterns:
            if re.search(pattern, value):
                return True
        
        # Additional Android-specific checks
        android_keywords = [
            'android', 'androidx', 'dalvik', 'art', 'activity', 'service',
            'receiver', 'provider', 'fragment', 'layout', 'drawable',
            'string', 'color', 'dimen', 'style', 'permission', 'feature'
        ]
        
        value_lower = value.lower()
        
        # Check if it's a class name pattern with Android keywords
        if ('/' in value or '.' in value) and any(keyword in value_lower for keyword in android_keywords):
            return True
        
        # Check for Android method signatures
        if re.match(r'^[a-z][a-zA-Z0-9]*\([^)]*\).*$', value):
            return any(keyword in value_lower for keyword in android_keywords)
        
        return False
    
    def is_test_context(self, code_context: CodeContext) -> bool:
        """
        Determine if the code context indicates test code.
        
        Args:
            code_context: The code context to analyze
            
        Returns:
            True if the context indicates test code, False otherwise
        """
        # Check file path indicators
        if code_context.file_path:
            for pattern in self.test_indicators['file_patterns']:
                if re.search(pattern, code_context.file_path, re.IGNORECASE):
                    return True
        
        # Check class name indicators
        for class_name in code_context.class_names:
            for pattern in self.test_indicators['class_patterns']:
                if re.search(pattern, class_name):
                    return True
        
        # Check import indicators
        for import_stmt in code_context.imports:
            for pattern in self.test_indicators['import_patterns']:
                if re.search(pattern, import_stmt):
                    return True
        
        # Check method signatures for test indicators
        for method in code_context.method_signatures:
            if re.search(r'(?i)\b(test|mock|stub|fake|should|expect|verify|assert)', method):
                return True
        
        # Check surrounding lines for test keywords
        test_keywords = ['@Test', '@Mock', '@Before', '@After', '@Spy', 'junit', 'mockito', 'assert']
        for line in code_context.surrounding_lines:
            if any(keyword in line for keyword in test_keywords):
                return True
        
        return False
    
    def calculate_entropy(self, string: str) -> float:
        """
        Calculate the Shannon entropy of a string.
        
        Args:
            string: The string to analyze
            
        Returns:
            The Shannon entropy value (higher values indicate more randomness)
        """
        if not string:
            return 0.0
        
        # Count character frequencies
        counter = Counter(string)
        length = len(string)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def has_high_entropy(self, value: str, min_entropy: float = 4.0) -> bool:
        """
        Check if a string has high entropy (indicative of randomness/encoding).
        
        Args:
            value: The string to check
            min_entropy: Minimum entropy threshold
            
        Returns:
            True if the string has high entropy, False otherwise
        """
        if len(value) < 8:  # Too short to meaningfully calculate entropy
            return False
        
        # First check for obvious low-entropy patterns
        if self._is_sequential_pattern(value):
            return False  # Sequential patterns are not high entropy regardless of calculated entropy
        
        # Determine string type and use appropriate threshold
        actual_threshold = min_entropy
        
        # Detect hex strings (only contains hex chars)
        if re.match(r'^[0-9a-fA-F]+$', value) and len(value) >= 16:
            actual_threshold = self.entropy_thresholds['hex']
            
        # Detect base64-like strings (must contain mixed case and/or numbers/symbols)
        elif (re.match(r'^[A-Za-z0-9+/=]+$', value) and 
              (len(value) % 4 == 0 or value.endswith('=')) and
              not re.match(r'^[a-z]+$', value) and  # Not purely lowercase
              not re.match(r'^[A-Z]+$', value)):    # Not purely uppercase
            actual_threshold = self.entropy_thresholds['base64']
            
        # For alphabetic sequences, use higher threshold to avoid false positives
        elif re.match(r'^[a-zA-Z]+$', value):
            # Pure alphabetic strings need much higher threshold to be considered high entropy
            actual_threshold = 5.5  # Much higher threshold for pure alphabetic strings
        
        entropy = self.calculate_entropy(value)
        return entropy >= actual_threshold
    
    def _is_sequential_pattern(self, value: str) -> bool:
        """
        Check if a string is a sequential pattern (like alphabetic sequence).
        
        Args:
            value: The string to check
            
        Returns:
            True if the string appears to be a sequential pattern
        """
        if len(value) < 4:
            return False
        
        # Check for alphabetic sequences (both ascending and descending)
        is_ascending = True
        is_descending = True
        
        for i in range(1, len(value)):
            prev_char = value[i-1].lower()
            curr_char = value[i].lower()
            
            # Check ascending sequence
            if ord(curr_char) != ord(prev_char) + 1:
                is_ascending = False
                
            # Check descending sequence
            if ord(curr_char) != ord(prev_char) - 1:
                is_descending = False
                
            if not is_ascending and not is_descending:
                break
        
        # If more than 75% of the string is sequential, consider it a pattern
        if is_ascending or is_descending:
            return True
        
        # Check for other common patterns
        # Repeating substrings
        for substr_len in [2, 3, 4]:
            if len(value) >= substr_len * 3:  # At least 3 repetitions
                substr = value[:substr_len]
                if value.startswith(substr * (len(value) // substr_len)):
                    return True
        
        return False
    
    def get_false_positive_indicators(self, finding: Dict[str, Any], 
                                    code_context: CodeContext) -> List[FalsePositiveIndicator]:
        """
        Analyze a finding and generate false positive indicators.
        
        Args:
            finding: The security finding to analyze
            code_context: The code context for the finding
            
        Returns:
            List of false positive indicators with confidence scores
        """
        indicators = []
        value = finding.get('value', '')
        finding_type = finding.get('type', '')
        finding.get('location', '')
        
        # 1. Placeholder value detection
        if self.is_placeholder_value(value):
            indicators.append(FalsePositiveIndicator(
                indicator_type='placeholder_value',
                indicator_value=value[:50],
                confidence=0.9,
                description=f'Value appears to be a placeholder: {value[:50]}...',
                source='pattern_matching'
            ))
        
        # 2. Test context detection
        if self.is_test_context(code_context):
            indicators.append(FalsePositiveIndicator(
                indicator_type='test_context',
                indicator_value=code_context.file_path or 'test context detected',
                confidence=0.8,
                description='Finding is in test code context',
                source='code_analysis'
            ))
        
        # 3. Android system string detection
        if self.is_android_system_string(value):
            indicators.append(FalsePositiveIndicator(
                indicator_type='android_system_string',
                indicator_value=value[:50],
                confidence=0.95,
                description=f'Value appears to be Android system string: {value[:50]}...',
                source='pattern_matching'
            ))
        
        # 4. Low entropy check (for patterns that should have high entropy)
        should_have_high_entropy = any(keyword in finding_type.lower() for keyword in [
            'high entropy', 'base64', 'potential key', 'secret key', 'api key', 
            'token', 'credential', 'password'
        ])
        
        if should_have_high_entropy:
            if not self.has_high_entropy(value):
                indicators.append(FalsePositiveIndicator(
                    indicator_type='low_entropy',
                    indicator_value=f'entropy: {self.calculate_entropy(value):.2f}',
                    confidence=0.7,
                    description=f'Value has low entropy for claimed type: {self.calculate_entropy(value):.2f}',
                    source='entropy_analysis'
                ))
        
        # 5. Common false positive patterns
        false_positive_patterns = [
            (r'^\d+$', 'numeric_only', 0.6, 'Value is purely numeric'),
            (r'^[a-zA-Z]+$', 'alphabetic_only', 0.5, 'Value is purely alphabetic'),
            (r'^(true|false|null|undefined|none|nil)$', 'boolean_null', 0.8, 'Value is boolean or null'),
            (r'^https?://', 'url_pattern', 0.3, 'Value is a URL'),
            (r'\.(?:com|org|net|gov|edu)(?:/|$)', 'domain_pattern', 0.4, 'Value contains domain name'),
            (r'(?i)\b(version|build|debug|release)\b', 'version_info', 0.5, 'Value appears to be version information'),
        ]
        
        for pattern, indicator_type, confidence, description in false_positive_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                indicators.append(FalsePositiveIndicator(
                    indicator_type=indicator_type,
                    indicator_value=value[:30],
                    confidence=confidence,
                    description=description,
                    source='pattern_matching'
                ))
                break  # Only add the first matching pattern
        
        # 6. Context-specific indicators
        if code_context.has_test_indicators():
            indicators.append(FalsePositiveIndicator(
                indicator_type='test_indicators',
                indicator_value='multiple test indicators found',
                confidence=0.75,
                description='Multiple test indicators found in code context',
                source='code_analysis'
            ))
        
        if code_context.has_configuration_indicators():
            indicators.append(FalsePositiveIndicator(
                indicator_type='configuration_context',
                indicator_value='configuration context detected',
                confidence=0.4,  # Lower confidence as config can contain real secrets
                description='Value found in configuration context',
                source='code_analysis'
            ))
        
        # 7. Length-based indicators
        if len(value) < 8:
            indicators.append(FalsePositiveIndicator(
                indicator_type='too_short',
                indicator_value=f'length: {len(value)}',
                confidence=0.6,
                description=f'Value is too short to be a meaningful secret: {len(value)} characters',
                source='length_analysis'
            ))
        elif len(value) > 200:
            indicators.append(FalsePositiveIndicator(
                indicator_type='too_long',
                indicator_value=f'length: {len(value)}',
                confidence=0.5,
                description=f'Value is unusually long: {len(value)} characters',
                source='length_analysis'
            ))
        
        return indicators
    
    def calculate_false_positive_probability(self, indicators: List[FalsePositiveIndicator]) -> float:
        """
        Calculate the overall false positive probability based on indicators.
        
        Args:
            indicators: List of false positive indicators
            
        Returns:
            Probability (0.0 to 1.0) that the finding is a false positive
        """
        if not indicators:
            return 0.1  # Low default probability when no indicators
        
        # Weight indicators by their confidence and combine probabilities
        # Using a Bayesian-like approach where multiple weak indicators
        # can combine to create strong evidence
        
        combined_probability = 0.1  # Base probability
        
        # Group indicators by type to avoid over-weighting
        indicator_groups = {}
        for indicator in indicators:
            group = indicator.indicator_type
            if group not in indicator_groups:
                indicator_groups[group] = []
            indicator_groups[group].append(indicator)
        
        # Calculate combined probability for each group
        for group, group_indicators in indicator_groups.items():
            # Take the highest confidence indicator from each group
            max_confidence = max(ind.confidence for ind in group_indicators)
            
            # Apply weights based on indicator type
            weight_map = {
                'placeholder_value': 1.0,      # Highest weight
                'android_system_string': 1.0,  # Highest weight
                'test_context': 0.9,           # Very high weight
                'test_indicators': 0.8,        # High weight
                'low_entropy': 0.7,            # Medium-high weight
                'boolean_null': 0.6,           # Medium weight
                'numeric_only': 0.5,           # Medium-low weight
                'configuration_context': 0.3,  # Low weight (configs can have secrets)
                'too_short': 0.4,              # Low-medium weight
                'too_long': 0.3,               # Low weight
            }
            
            weight = weight_map.get(group, 0.5)  # Default weight
            weighted_confidence = max_confidence * weight
            
            # Combine probabilities (avoiding over-weighting)
            combined_probability = combined_probability + (1 - combined_probability) * weighted_confidence
        
        # Cap at 0.99 to avoid absolute certainty
        return min(0.99, combined_probability)
    
    def filter_finding(self, finding: Dict[str, Any], code_context: CodeContext) -> ContextualFinding:
        """
        Filter a single finding and create a contextual finding with false positive analysis.
        
        Args:
            finding: The original security finding
            code_context: The code context for the finding
            
        Returns:
            ContextualFinding with enhanced false positive analysis
        """
        # Generate false positive indicators
        fp_indicators = self.get_false_positive_indicators(finding, code_context)
        
        # Calculate false positive probability
        fp_probability = self.calculate_false_positive_probability(fp_indicators)
        
        # Create context metadata
        context_metadata = ContextMetadata(
            false_positive_probability=fp_probability,
            analysis_confidence=self._determine_analysis_confidence(fp_indicators),
        )
        
        # Create contextual finding
        contextual_finding = ContextualFinding(
            original_finding=finding,
            context_metadata=context_metadata,
            false_positive_indicators=[ind.to_dict() for ind in fp_indicators]
        )
        
        # Adjust severity based on false positive probability
        if fp_probability > 0.8:
            contextual_finding.adjusted_severity = 'LOW'
        elif fp_probability > 0.5:
            contextual_finding.adjusted_severity = 'MEDIUM'
        
        self.logger.debug(f"Filtered finding: {finding.get('type', 'Unknown')} -> FP probability: {fp_probability:.2f}")
        
        return contextual_finding
    
    def filter_findings(self, findings: List[Dict[str, Any]], 
                       code_contexts: List[CodeContext]) -> List[ContextualFinding]:
        """
        Filter multiple findings with their corresponding code contexts.
        
        Args:
            findings: List of security findings to filter
            code_contexts: List of code contexts corresponding to findings
            
        Returns:
            List of ContextualFindings with false positive analysis
            
        Raises:
            ValueError: If the number of findings and contexts don't match
        """
        if len(findings) != len(code_contexts):
            raise ValueError("Number of findings and contexts must match")
        
        contextual_findings = []
        
        for finding, context in zip(findings, code_contexts):
            try:
                contextual_finding = self.filter_finding(finding, context)
                contextual_findings.append(contextual_finding)
            except Exception as e:
                self.logger.error(f"Error filtering finding {finding.get('type', 'Unknown')}: {str(e)}")
                # Create a basic contextual finding on error
                contextual_findings.append(ContextualFinding.from_original_finding(finding))
        
        self.logger.info(f"Filtered {len(findings)} findings, "
                        f"{len([f for f in contextual_findings if f.is_likely_false_positive])} likely false positives")
        
        return contextual_findings
    
    def _determine_analysis_confidence(self, indicators: List[FalsePositiveIndicator]) -> ContextConfidence:
        """
        Determine the confidence level of the analysis based on available indicators.
        
        Args:
            indicators: List of false positive indicators
            
        Returns:
            ContextConfidence level
        """
        if not indicators:
            return ContextConfidence.LOW
        
        # Calculate average confidence
        avg_confidence = sum(ind.confidence for ind in indicators) / len(indicators)
        
        if avg_confidence >= 0.8:
            return ContextConfidence.VERY_HIGH
        elif avg_confidence >= 0.6:
            return ContextConfidence.HIGH
        elif avg_confidence >= 0.4:
            return ContextConfidence.MEDIUM
        elif avg_confidence >= 0.2:
            return ContextConfidence.LOW
        else:
            return ContextConfidence.VERY_LOW