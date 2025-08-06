#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment

@register_assessment('sensitive_data')
class SensitiveDataAssessment(BaseSecurityAssessment):
    """OWASP A02:2021 - Cryptographic Failures / Sensitive Data Exposure assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A02:2021-Cryptographic Failures"
        
        self.pii_patterns = config.get('pii_patterns', ['email', 'phone', 'ssn', 'credit_card'])
        self.crypto_keys_check = config.get('crypto_keys_check', True)
        
        # Enhanced key detection configuration
        self.key_detection_config = config.get('key_detection', {})
        self.key_detection_enabled = self.key_detection_config.get('enabled', True)
        
        # Pattern enablement
        pattern_config = self.key_detection_config.get('patterns', {})
        self.enabled_patterns = {
            'pem_keys': pattern_config.get('pem_keys', True),
            'ssh_keys': pattern_config.get('ssh_keys', True),
            'jwt_tokens': pattern_config.get('jwt_tokens', True),
            'api_keys': pattern_config.get('api_keys', True),
            'base64_keys': pattern_config.get('base64_keys', True),
            'hex_keys': pattern_config.get('hex_keys', True),
            'database_connections': pattern_config.get('database_connections', True),
            'high_entropy_strings': pattern_config.get('high_entropy_strings', True)
        }
        
        # Entropy thresholds
        entropy_config = self.key_detection_config.get('entropy_thresholds', {})
        self.entropy_thresholds = {
            'min_base64_entropy': entropy_config.get('min_base64_entropy', 4.0),
            'min_hex_entropy': entropy_config.get('min_hex_entropy', 3.5),
            'min_generic_entropy': entropy_config.get('min_generic_entropy', 5.0)
        }
        
        # Length filters
        length_config = self.key_detection_config.get('length_filters', {})
        self.length_filters = {
            'min_key_length': length_config.get('min_key_length', 16),
            'max_key_length': length_config.get('max_key_length', 512)
        }
        
        # Context detection settings
        context_config = self.key_detection_config.get('context_detection', {})
        self.context_detection_enabled = context_config.get('enabled', True)
        self.context_strict_mode = context_config.get('strict_mode', False)
        
        # PII detection patterns
        self.pii_regex_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        }
        
        # Enhanced hardcoded key detection patterns (integrated from secret-finder)
        self.key_detection_patterns = {
            # CRITICAL SEVERITY PATTERNS
            # Private Keys - Enhanced patterns from secret-finder
            'pem_private_key': {
                'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY(?: BLOCK)?-----',
                'description': 'Private Key',
                'severity': 'CRITICAL'
            },
            'ssh_private_key': {
                'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+/\s=]+-----END OPENSSH PRIVATE KEY-----',
                'description': 'SSH private key',
                'severity': 'CRITICAL'
            },
            
            # AWS Credentials - Enhanced from secret-finder
            'aws_access_key': {
                'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
                'description': 'AWS Access Key ID',
                'severity': 'CRITICAL'
            },
            'aws_secret_key': {
                'pattern': r'(?i)aws(?:.{0,20})?(?:secret|key|token).{0,20}?[\'"]([A-Za-z0-9/+=]{40})[\'"]',
                'description': 'AWS Secret Access Key',
                'severity': 'CRITICAL'
            },
            
            # GitHub Tokens - Enhanced patterns
            'github_token': {
                'pattern': r'ghp_[0-9a-zA-Z]{36}',
                'description': 'GitHub Token',
                'severity': 'CRITICAL'
            },
            'github_fine_grained_token': {
                'pattern': r'github_pat_[0-9a-zA-Z_]{82}',
                'description': 'GitHub Fine-Grained Token',
                'severity': 'CRITICAL'
            },
            'github_token_in_url': {
                'pattern': r'[a-zA-Z0-9_-]*:([a-zA-Z0-9_\-]+)@github\.com',
                'description': 'GitHub Token in URL',
                'severity': 'CRITICAL'
            },
            
            # Google Credentials
            'google_oauth_token': {
                'pattern': r'ya29\.[0-9A-Za-z\-_]+',
                'description': 'Google OAuth Token',
                'severity': 'CRITICAL'
            },
            'google_service_account': {
                'pattern': r'"type":\s*"service_account"',
                'description': 'Google (GCP) Service Account',
                'severity': 'CRITICAL'
            },
            
            # Firebase & Other Critical
            'firebase_cloud_messaging_key': {
                'pattern': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
                'description': 'Firebase Cloud Messaging Key',
                'severity': 'CRITICAL'
            },
            'password_in_url': {
                'pattern': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:([^/\s:@]{3,20})@.{1,100}["\'\s]',
                'description': 'Password in URL',
                'severity': 'CRITICAL'
            },
            
            # HIGH SEVERITY PATTERNS
            # Generic Password/API Key Patterns
            'generic_password': {
                'pattern': r'(?i)\b(?:password|pass|pwd|passwd)\b\s*[:=]\s*[\'"]?([^\s\'"/\\,;<>]{8,})[\'"]?',
                'description': 'Password',
                'severity': 'HIGH'
            },
            'generic_api_key': {
                'pattern': r'(?i)\b(?:api_key|apikey|api-key|access_key|access-key|secret_key|secret-key)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-_.]{20,})[\'"]?',
                'description': 'Generic API Key',
                'severity': 'HIGH'
            },
            'generic_secret': {
                'pattern': r'(?i)\bsecret\b.*[\'"]([0-9a-zA-Z]{32,45})[\'"]',
                'description': 'Generic Secret',
                'severity': 'HIGH'
            },
            
            # JWT tokens
            'jwt_token': {
                'pattern': r'ey[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*',
                'description': 'JWT Token',
                'severity': 'HIGH'
            },
            
            # Service-Specific High Severity
            'azure_client_secret': {
                'pattern': r'(?i)\b(?:azure_client_secret|client_secret)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-~_\\.]{30,})[\'"]?',
                'description': 'Azure Client Secret',
                'severity': 'HIGH'
            },
            'heroku_api_key': {
                'pattern': r'(?i)\b(?:heroku_api_key|heroku-api-key)\b\s*[:=]\s*[\'"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\'"]?',
                'description': 'Heroku API Key',
                'severity': 'HIGH'
            },
            'stripe_api_key': {
                'pattern': r'(?:sk|pk)_live_[0-9a-zA-Z]{24}',
                'description': 'Stripe API Key',
                'severity': 'HIGH'
            },
            'discord_bot_token': {
                'pattern': r'[M-Z][a-zA-Z0-9\-_]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,}',
                'description': 'Discord Bot Token',
                'severity': 'HIGH'
            },
            'gitlab_personal_token': {
                'pattern': r'glpat-[0-9a-zA-Z\-_]{20}',
                'description': 'GitLab Personal Token',
                'severity': 'HIGH'
            },
            'amazon_mws_auth_token': {
                'pattern': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                'description': 'Amazon MWS Auth Token',
                'severity': 'HIGH'
            },
            'facebook_access_token': {
                'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+',
                'description': 'Facebook Access Token',
                'severity': 'HIGH'
            },
            'facebook_oauth_secret': {
                'pattern': r'(?i)facebook.*[\'"]([0-9a-f]{32})[\'"]',
                'description': 'Facebook OAuth Secret',
                'severity': 'HIGH'
            },
            'mailchimp_api_key': {
                'pattern': r'[0-9a-f]{32}-us[0-9]{1,2}',
                'description': 'MailChimp API Key',
                'severity': 'HIGH'
            },
            'mailgun_api_key': {
                'pattern': r'key-[0-9a-zA-Z]{32}',
                'description': 'Mailgun API Key',
                'severity': 'HIGH'
            },
            'picatic_api_key': {
                'pattern': r'sk_live_[0-9a-z]{32}',
                'description': 'Picatic API Key',
                'severity': 'HIGH'
            },
            'square_access_token': {
                'pattern': r'sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
                'description': 'Square Access Token',
                'severity': 'HIGH'
            },
            'square_oauth_secret': {
                'pattern': r'sq0csp-[0-9A-Za-z\-_]{43}',
                'description': 'Square OAuth Secret',
                'severity': 'HIGH'
            },
            'twitter_access_token': {
                'pattern': r'(?i)\btwitter\b.*([1-9][0-9]+-[0-9a-zA-Z]{40})',
                'description': 'Twitter Access Token',
                'severity': 'HIGH'
            },
            'twitter_oauth_secret': {
                'pattern': r'(?i)\btwitter\b.*[\'"]([0-9a-zA-Z]{35,44})[\'"]',
                'description': 'Twitter OAuth Secret',
                'severity': 'HIGH'
            },
            'authorization_basic': {
                'pattern': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
                'description': 'Authorization Basic',
                'severity': 'HIGH'
            },
            'authorization_bearer': {
                'pattern': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
                'description': 'Authorization Bearer',
                'severity': 'HIGH'
            },
            'slack_token': {
                'pattern': r'xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
                'description': 'Slack Token',
                'severity': 'HIGH'
            },
            
            # MEDIUM SEVERITY PATTERNS
            'google_cloud_api_key': {
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'description': 'Google Cloud API Key',
                'severity': 'MEDIUM'
            },
            'slack_token_legacy': {
                'pattern': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
                'description': 'Slack Token (Legacy)',
                'severity': 'MEDIUM'
            },
            
            # Database Connection URIs
            'mongodb_uri': {
                'pattern': r'mongodb(?:\+srv)?:\/\/[^\s]+',
                'description': 'MongoDB URI',
                'severity': 'MEDIUM'
            },
            'postgresql_uri': {
                'pattern': r'postgres(?:ql)?:\/\/[^\s]+',
                'description': 'PostgreSQL URI',
                'severity': 'MEDIUM'
            },
            'mysql_uri': {
                'pattern': r'mysql:\/\/[^\s]+',
                'description': 'MySQL URI',
                'severity': 'MEDIUM'
            },
            'redis_uri': {
                'pattern': r'redis:\/\/[^\s]+',
                'description': 'Redis URI',
                'severity': 'MEDIUM'
            },
            'cloudinary_url': {
                'pattern': r'cloudinary://[^\s]+',
                'description': 'Cloudinary URL',
                'severity': 'MEDIUM'
            },
            'firebase_url': {
                'pattern': r'[^"\']+\.firebaseio\.com',
                'description': 'Firebase URL',
                'severity': 'MEDIUM'
            },
            'slack_webhook_url': {
                'pattern': r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                'description': 'Slack Webhook URL',
                'severity': 'MEDIUM'
            },
            
            # SSH Public Keys and Certificates
            'ssh_public_key': {
                'pattern': r'ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/]+=*',
                'description': 'SSH public key',
                'severity': 'MEDIUM'
            },
            'pem_certificate': {
                'pattern': r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/\s=]+-----END CERTIFICATE-----',
                'description': 'PEM-formatted certificate',
                'severity': 'MEDIUM'
            },
            
            # Hex encoded keys
            'hex_key_256': {
                'pattern': r'[a-fA-F0-9]{64}',
                'description': '256-bit hex key',
                'severity': 'MEDIUM'
            },
            'hex_key_128': {
                'pattern': r'[a-fA-F0-9]{32}',
                'description': '128-bit hex key',
                'severity': 'MEDIUM'
            },
            
            # LOW SEVERITY PATTERNS
            'jenkins_api_token': {
                'pattern': r'11[0-9a-f]{32}',
                'description': 'Jenkins API Token',
                'severity': 'LOW'
            },
            'stripe_restricted_key': {
                'pattern': r'rk_live_[0-9a-zA-Z]{24}',
                'description': 'Stripe Restricted Key',
                'severity': 'LOW'
            },
            'paypal_braintree_token': {
                'pattern': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                'description': 'PayPal Braintree Token',
                'severity': 'LOW'
            },
            'google_captcha_key': {
                'pattern': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
                'description': 'Google Captcha Key',
                'severity': 'LOW'
            },
            's3_bucket_url': {
                'pattern': r'[a-zA-Z0-9._-]+\.s3\.amazonaws\.com',
                'description': 'S3 Bucket URL',
                'severity': 'LOW'
            },
            
            # Base64 encoded keys (high entropy)
            'base64_key_long': {
                'pattern': r'[A-Za-z0-9+/]{64,}={0,2}',
                'description': 'Long Base64 encoded string (potential key)',
                'severity': 'LOW',
                'min_entropy': 4.5
            },
            'base64_key_medium': {
                'pattern': r'[A-Za-z0-9+/]{32,63}={0,2}',
                'description': 'Medium Base64 encoded string (potential key)',
                'severity': 'LOW',
                'min_entropy': 4.0
            },
            
            # Generic high-entropy strings
            'high_entropy_string': {
                'pattern': r'[A-Za-z0-9+/=]{20,}',
                'description': 'High entropy string (potential key)',
                'severity': 'LOW',
                'min_entropy': 5.0,
                'max_length': 512
            }
        }
        
        # Context keywords that increase suspicion level
        self.key_context_keywords = {
            'high_risk': ['password', 'secret', 'private', 'key', 'token', 'credential', 'auth'],
            'crypto': ['aes', 'rsa', 'des', 'rc4', 'encrypt', 'decrypt', 'cipher', 'crypto'],
            'api': ['api', 'token', 'bearer', 'oauth', 'jwt', 'auth'],
            'database': ['db', 'database', 'connection', 'conn', 'sql', 'mysql', 'postgres']
        }
        
        # Legacy crypto patterns (kept for backward compatibility)
        self.crypto_patterns = [
            'DES', 'RC4', 'MD5', 'SHA1',
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key',
            'private_key', 'public_key', 'certificate', 'keystore'
        ]
        
        # Permissions that may indicate sensitive data access
        self.sensitive_permissions = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
            'READ_SMS', 'RECEIVE_SMS', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
            'CAMERA', 'RECORD_AUDIO', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR'
        ]
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Assess for sensitive data exposure vulnerabilities
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to sensitive data exposure
        """
        findings = []
        
        try:
            # Check for PII in strings
            pii_findings = self._assess_pii_exposure(analysis_results)
            findings.extend(pii_findings)
            
            # Check for crypto keys and secrets
            if self.crypto_keys_check and self.key_detection_enabled:
                crypto_findings = self._assess_crypto_keys_exposure(analysis_results)
                findings.extend(crypto_findings)
            
            # Check weak cryptographic algorithms
            weak_crypto_findings = self._assess_weak_cryptography(analysis_results)
            findings.extend(weak_crypto_findings)
            
            # Check sensitive permissions
            permission_findings = self._assess_sensitive_permissions(analysis_results)
            findings.extend(permission_findings)
            
        except Exception as e:
            self.logger.error(f"Sensitive data assessment failed: {str(e)}")
        
        return findings
    
    def _assess_pii_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for PII exposure in strings"""
        findings = []
        
        # Get string analysis results
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        if not isinstance(string_data, dict):
            return findings
        
        # Collect all strings for analysis
        all_strings = []
        for key in ['emails', 'urls', 'domains']:
            strings = string_data.get(key, [])
            if isinstance(strings, list):
                all_strings.extend(strings)
        
        pii_found = {}
        
        # Check for PII patterns
        for pii_type in self.pii_patterns:
            if pii_type in self.pii_regex_patterns:
                pattern = self.pii_regex_patterns[pii_type]
                matches = []
                
                for string in all_strings:
                    if isinstance(string, str):
                        if re.search(pattern, string):
                            matches.append(string[:50] + "..." if len(string) > 50 else string)
                
                if matches:
                    pii_found[pii_type] = matches
        
        # Also check emails from string analysis results
        emails = string_data.get('emails', [])
        if emails:
            pii_found['emails_detected'] = [email[:30] + "..." for email in emails[:5]]
        
        if pii_found:
            evidence = []
            for pii_type, matches in pii_found.items():
                evidence.append(f"{pii_type.upper()}: {len(matches)} instances found")
                evidence.extend([f"  - {match}" for match in matches[:3]])  # Show first 3
            
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Potential PII Exposure in Application Strings",
                description="Personal Identifiable Information (PII) patterns detected in application strings, which may indicate hardcoded sensitive data.",
                evidence=evidence,
                recommendations=[
                    "Remove all hardcoded PII from the application",
                    "Use secure storage mechanisms for sensitive data",
                    "Implement proper data encryption for stored PII",
                    "Follow data minimization principles",
                    "Ensure compliance with privacy regulations (GDPR, CCPA, etc.)"
                ]
            ))
        
        return findings
    
    def _assess_crypto_keys_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for exposed cryptographic keys and secrets using comprehensive detection"""
        findings = []
        
        # Get string analysis results
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        if not isinstance(string_data, dict):
            return findings
        
        # Collect all strings from various sources
        all_strings = []
        
        # From string analysis results - include ALL string categories
        for key in ['emails', 'urls', 'domains', 'ip_addresses', 'interesting_strings', 'filtered_strings']:
            strings = string_data.get(key, [])
            if isinstance(strings, list):
                all_strings.extend(strings)
        
        # From Android properties
        android_props = string_data.get('android_properties', {})
        if isinstance(android_props, dict):
            all_strings.extend(android_props.keys())
            all_strings.extend([str(v) for v in android_props.values() if isinstance(v, str)])
        
        # Get raw strings from the string analysis if available
        raw_strings = string_data.get('all_strings', [])
        if isinstance(raw_strings, list):
            all_strings.extend(raw_strings)
            
        # Enhanced string extraction using behaviour analysis objects when available
        deep_strings_extracted = 0
        try:
            # Check if we have behaviour analysis results with stored androguard objects
            behaviour_results = analysis_results.get('behaviour_analysis', {})
            if hasattr(behaviour_results, 'androguard_objects'):
                androguard_objs = behaviour_results.androguard_objects
                analysis_mode = androguard_objs.get('mode', 'unknown')
                
                if analysis_mode == 'deep':
                    self.logger.info("🔍 Using DEEP analysis objects for enhanced secret detection")
                    
                    # Extract strings from DEX objects (similar to apk_api_key_extractor approach)
                    dex_obj = androguard_objs.get('dex_obj')
                    if dex_obj:
                        for i, dex in enumerate(dex_obj):
                            try:
                                dex_strings = dex.get_strings()
                                for string in dex_strings:
                                    string_val = str(string)
                                    if string_val and len(string_val.strip()) > 0:
                                        all_strings.append(string_val)
                                        deep_strings_extracted += 1
                                self.logger.debug(f"Extracted {len(dex_strings)} strings from DEX {i+1}")
                            except Exception as e:
                                self.logger.debug(f"Error extracting strings from DEX {i}: {e}")
                    
                    # Extract strings from analysis objects for method analysis (secret-finder style)
                    dx_obj = androguard_objs.get('dx_obj')
                    if dx_obj:
                        try:
                            # Get method analysis for more comprehensive secret detection
                            classes = dx_obj.get_classes()
                            for cls in classes:
                                try:
                                    # Get class source code for pattern matching
                                    source = cls.get_source()
                                    if source:
                                        # Split source into lines and add as potential strings
                                        lines = source.split('\n')
                                        for line in lines:
                                            line = line.strip()
                                            if line and len(line) > 10:  # Skip very short lines
                                                all_strings.append(line)
                                                deep_strings_extracted += 1
                                                
                                    # Extract method names and field names as potential secrets
                                    for method in cls.get_methods():
                                        method_name = method.get_method().get_name()
                                        if method_name and len(method_name) > 5:
                                            all_strings.append(method_name)
                                            deep_strings_extracted += 1
                                            
                                except Exception as e:
                                    self.logger.debug(f"Error analyzing class {cls.name}: {e}")
                                    
                        except Exception as e:
                            self.logger.debug(f"Error in analysis object string extraction: {e}")
                            
                elif analysis_mode == 'fast':
                    self.logger.info("⚡ Using FAST analysis mode - basic secret detection enabled")
                    
            # Fallback: try to get strings from APK overview
            apk_overview = analysis_results.get('apk_overview', {})
            if hasattr(apk_overview, 'to_dict'):
                apk_data = apk_overview.to_dict()
            else:
                apk_data = apk_overview
            
            if isinstance(apk_data, dict):
                context_strings = apk_data.get('context_strings', [])
                if isinstance(context_strings, list):
                    all_strings.extend(context_strings)
                    
        except Exception as e:
            self.logger.debug(f"Could not extract additional strings from analysis objects: {e}")
            
        if deep_strings_extracted > 0:
            self.logger.info(f"🎯 Enhanced analysis: extracted {deep_strings_extracted} additional strings from DEX/code analysis")
        
        # Remove duplicates and filter out empty/None values
        unique_strings = list(set([s for s in all_strings if s and isinstance(s, str) and len(s.strip()) > 0]))
        self.logger.info(f"Analyzing {len(unique_strings)} unique strings for hardcoded secrets")
        
        # Detect hardcoded keys using advanced patterns
        detected_keys = self._detect_hardcoded_keys(unique_strings)
        
        # Group findings by severity with full key extraction
        critical_findings = []
        high_findings = []
        medium_findings = []
        low_findings = []
        
        # Store the actual detected secrets for JSON output
        detected_secrets = {
            'critical': [],
            'high': [],
            'medium': [], 
            'low': []
        }
        
        for detection in detected_keys:
            # Create detailed evidence entry with full key value
            evidence_entry = {
                'type': detection['type'],
                'severity': detection['severity'],
                'pattern_name': detection['pattern_name'],
                'value': detection['value'],  # Full key value preserved
                'full_context': detection.get('full_context', detection['value']),  # Context where found
                'location': f"String analysis",
                'preview': detection['value'][:100] + ('...' if len(detection['value']) > 100 else '')
            }
            
            # Format for terminal display (truncated)
            terminal_display = f"🔑 [{detection['severity']}] {detection['type']}: {evidence_entry['preview']}"
            
            if detection['severity'] == 'CRITICAL':
                critical_findings.append(terminal_display)
                detected_secrets['critical'].append(evidence_entry)
            elif detection['severity'] == 'HIGH':
                high_findings.append(terminal_display)
                detected_secrets['high'].append(evidence_entry)
            elif detection['severity'] == 'MEDIUM':
                medium_findings.append(terminal_display)
                detected_secrets['medium'].append(evidence_entry)
            else:
                low_findings.append(terminal_display)
                detected_secrets['low'].append(evidence_entry)
        
        # Create findings based on severity levels with secret-finder style messaging
        if critical_findings:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.CRITICAL,
                title=f"🔴 CRITICAL: {len(critical_findings)} Hard-coded Secrets Found",
                description=f"Found {len(critical_findings)} critical severity secrets that pose immediate security risks. These include private keys, AWS credentials, and other highly sensitive data that could lead to complete system compromise.",
                evidence=critical_findings[:10],
                recommendations=[
                    "🚨 IMMEDIATE ACTION REQUIRED: Remove all hardcoded critical secrets",
                    "🔐 Revoke and rotate all exposed credentials immediately",
                    "📱 Use Android Keystore for cryptographic key storage",
                    "🛡️ Implement secure secret management (e.g., HashiCorp Vault, AWS Secrets Manager)",
                    "🔍 Conduct comprehensive security audit for additional exposures",
                    "📋 Establish secure development practices and secret scanning in CI/CD"
                ],
                additional_data={
                    'detected_secrets': detected_secrets['critical'],
                    'total_secrets_found': len(detected_secrets['critical']),
                    'analysis_metadata': {
                        'strings_analyzed': len(unique_strings),
                        'detection_patterns_used': len(self.key_detection_patterns)
                    }
                }
            ))
        
        if high_findings:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title=f"🟠 HIGH: {len(high_findings)} API Keys and Tokens Exposed",
                description=f"Discovered {len(high_findings)} high-risk credentials including API keys, authentication tokens, and service credentials that could enable unauthorized access to external services.",
                evidence=high_findings[:10],
                recommendations=[
                    "🔑 Remove all hardcoded API keys and authentication tokens",
                    "🔄 Rotate exposed credentials and monitor for unauthorized usage",
                    "⚙️ Use environment variables or secure configuration management",
                    "🔒 Implement proper OAuth2/JWT authentication flows",
                    "📊 Set up monitoring and alerting for credential usage",
                    "🛠️ Integrate secret scanning tools into development workflow"
                ],
                additional_data={
                    'detected_secrets': detected_secrets['high'],
                    'total_secrets_found': len(detected_secrets['high']),
                    'analysis_metadata': {
                        'strings_analyzed': len(unique_strings),
                        'detection_patterns_used': len(self.key_detection_patterns)
                    }
                }
            ))
        
        if medium_findings:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title=f"🟡 MEDIUM: {len(medium_findings)} Potential Secrets Identified",
                description=f"Identified {len(medium_findings)} medium-risk patterns including database URIs, configuration keys, and other potentially sensitive information that should be reviewed and secured.",
                evidence=medium_findings[:15],
                recommendations=[
                    "🔍 Review all identified patterns to confirm if they contain actual secrets",
                    "🛡️ Replace confirmed sensitive data with secure configuration",
                    "📝 Implement data classification and handling policies",
                    "🔐 Use secure storage mechanisms for configuration data",
                    "📋 Document and categorize legitimate high-entropy strings"
                ],
                additional_data={
                    'detected_secrets': detected_secrets['medium'],
                    'total_secrets_found': len(detected_secrets['medium']),
                    'analysis_metadata': {
                        'strings_analyzed': len(unique_strings),
                        'detection_patterns_used': len(self.key_detection_patterns)
                    }
                }
            ))
        
        if low_findings and len(low_findings) > 5:  # Only report low findings if there are many
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.LOW,
                title=f"🔵 LOW: {len(low_findings)} Suspicious Patterns Detected",
                description=f"Found {len(low_findings)} low-risk patterns with high entropy or specific formats that may indicate encoded secrets or API keys. These should be reviewed to rule out false positives.",
                evidence=[f"📊 Total suspicious patterns found: {len(low_findings)}"] + low_findings[:5],
                recommendations=[
                    "🔍 Review suspicious patterns for potential secrets",
                    "⚡ Implement entropy-based secret detection in development pipeline",
                    "📚 Establish coding standards for handling non-secret high-entropy data",
                    "📝 Create whitelist for legitimate high-entropy strings"
                ],
                additional_data={
                    'detected_secrets': detected_secrets['low'],
                    'total_secrets_found': len(detected_secrets['low']),
                    'analysis_metadata': {
                        'strings_analyzed': len(unique_strings),
                        'detection_patterns_used': len(self.key_detection_patterns)
                    }
                }
            ))
        
        return findings
    
    def _detect_hardcoded_keys(self, strings: List[str]) -> List[Dict[str, str]]:
        """Detect hardcoded keys using comprehensive pattern matching"""
        detections = []
        
        for string in strings:
            if not isinstance(string, str):
                continue
            
            # Apply length filters
            if len(string) < self.length_filters['min_key_length'] or len(string) > self.length_filters['max_key_length']:
                continue
            
            # Check each detection pattern
            for key_type, pattern_config in self.key_detection_patterns.items():
                # Check if this pattern type is enabled
                if not self._is_pattern_enabled(key_type):
                    continue
                
                pattern = pattern_config['pattern']
                
                try:
                    match = re.search(pattern, string, re.IGNORECASE | re.MULTILINE)
                    if match:
                        # Extract the actual match (might be a capture group)
                        matched_value = match.group(1) if match.groups() else match.group(0)
                        
                        # Additional validation checks
                        if self._validate_key_detection(matched_value, pattern_config, key_type):
                            detections.append({
                                'type': pattern_config['description'],
                                'value': matched_value,  # Use the extracted match, not the full string
                                'full_context': string,  # Keep the full context for reference
                                'severity': pattern_config['severity'],
                                'pattern_name': key_type
                            })
                            break  # Don't match multiple patterns for the same string
                            
                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern for {key_type}: {e}")
                    continue
        
        return detections
    
    def _is_pattern_enabled(self, key_type: str) -> bool:
        """Check if a pattern type is enabled in configuration"""
        # Map pattern names to configuration keys - updated with all new patterns
        pattern_mapping = {
            # Critical patterns
            'pem_private_key': 'pem_keys',
            'ssh_private_key': 'ssh_keys',
            'aws_access_key': 'api_keys',
            'aws_secret_key': 'api_keys',
            'github_token': 'api_keys',
            'github_fine_grained_token': 'api_keys',
            'github_token_in_url': 'api_keys',
            'google_oauth_token': 'api_keys',
            'google_service_account': 'api_keys',
            'firebase_cloud_messaging_key': 'api_keys',
            'password_in_url': 'api_keys',
            
            # High severity patterns
            'generic_password': 'api_keys',
            'generic_api_key': 'api_keys',
            'generic_secret': 'api_keys',
            'jwt_token': 'jwt_tokens',
            'azure_client_secret': 'api_keys',
            'heroku_api_key': 'api_keys',
            'stripe_api_key': 'api_keys',
            'discord_bot_token': 'api_keys',
            'gitlab_personal_token': 'api_keys',
            'amazon_mws_auth_token': 'api_keys',
            'facebook_access_token': 'api_keys',
            'facebook_oauth_secret': 'api_keys',
            'mailchimp_api_key': 'api_keys',
            'mailgun_api_key': 'api_keys',
            'picatic_api_key': 'api_keys',
            'square_access_token': 'api_keys',
            'square_oauth_secret': 'api_keys',
            'twitter_access_token': 'api_keys',
            'twitter_oauth_secret': 'api_keys',
            'authorization_basic': 'api_keys',
            'authorization_bearer': 'api_keys',
            'slack_token': 'api_keys',
            
            # Medium severity patterns
            'google_cloud_api_key': 'api_keys',
            'slack_token_legacy': 'api_keys',
            'mongodb_uri': 'database_connections',
            'postgresql_uri': 'database_connections',
            'mysql_uri': 'database_connections',
            'redis_uri': 'database_connections',
            'cloudinary_url': 'database_connections',
            'firebase_url': 'database_connections',
            'slack_webhook_url': 'api_keys',
            'ssh_public_key': 'ssh_keys',
            'pem_certificate': 'pem_keys',
            'hex_key_256': 'hex_keys',
            'hex_key_128': 'hex_keys',
            
            # Low severity patterns
            'jenkins_api_token': 'api_keys',
            'stripe_restricted_key': 'api_keys',
            'paypal_braintree_token': 'api_keys',
            'google_captcha_key': 'api_keys',
            's3_bucket_url': 'api_keys',
            'base64_key_long': 'base64_keys',
            'base64_key_medium': 'base64_keys',
            'high_entropy_string': 'high_entropy_strings'
        }
        
        config_key = pattern_mapping.get(key_type, 'api_keys')  # Default to api_keys
        return self.enabled_patterns.get(config_key, True)
    
    def _validate_key_detection(self, string: str, pattern_config: Dict[str, Any], key_type: str) -> bool:
        """Validate key detection with additional checks"""
        
        # Check minimum entropy using configured thresholds
        min_entropy = pattern_config.get('min_entropy')
        if min_entropy is None:
            # Use configured entropy thresholds based on key type
            if 'base64' in key_type:
                min_entropy = self.entropy_thresholds['min_base64_entropy']
            elif 'hex' in key_type:
                min_entropy = self.entropy_thresholds['min_hex_entropy']
            elif key_type == 'high_entropy_string':
                min_entropy = self.entropy_thresholds['min_generic_entropy']
        
        if min_entropy and self._calculate_entropy(string) < min_entropy:
            return False
        
        # Check maximum length if specified
        max_length = pattern_config.get('max_length')
        if max_length and len(string) > max_length:
            return False
        
        # Check if context is required (if context detection is enabled)
        context_required = pattern_config.get('context_required', [])
        if context_required and self.context_detection_enabled:
            if not self._has_required_context(string, context_required):
                # In strict mode, require context for all matches with context_required
                if self.context_strict_mode:
                    return False
                # In non-strict mode, just log a warning but allow the detection
                self.logger.debug(f"Key detected without required context: {key_type}")
        
        # Skip common false positives
        if self._is_false_positive(string):
            return False
        
        return True
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        import math
        from collections import Counter
        
        # Get frequency of each character
        counter = Counter(string)
        length = len(string)
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_required_context(self, string: str, required_keywords: List[str]) -> bool:
        """Check if string has required context keywords nearby"""
        string_lower = string.lower()
        
        # Simple context check - look for keywords in the string itself
        for keyword in required_keywords:
            if keyword.lower() in string_lower:
                return True
        
        return False
    
    def _is_false_positive(self, string: str) -> bool:
        """Check for common false positives - enhanced to reduce noise from expanded patterns"""
        string_lower = string.lower()
        
        # Common false positive patterns
        false_positives = [
            # Android/Java class names and packages
            r'^(com|android|java|javax)\.',
            r'\.class$',
            r'\.java$',
            r'\.xml$',
            r'\.png$',
            r'\.jpg$',
            
            # Common placeholder values - expanded set
            r'^(test|example|sample|demo|placeholder|dummy)',
            r'^(your_api_key|your_token|your_secret|insert_key_here|api_key_here)',
            r'^(null|undefined|none|nil|empty)$',
            r'(test|demo|sample|example).*key',
            r'(fake|mock|stub).*',
            
            # Development/debugging strings
            r'^(debug|log|print|console)',
            r'lorem.*ipsum',
            r'hello.*world',
            
            # Repeated characters (unlikely to be real keys)
            r'^(.)\1{10,}$',
            r'^(a|b|c|x|y|z){20,}$',
            
            # URLs and domains - expanded
            r'^https?://',
            r'\.(?:com|org|net|edu|gov|mil|int|co\.uk|de|fr|jp)(?:/|$)',
            r'localhost',
            r'127\.0\.0\.1',
            r'0\.0\.0\.0',
            
            # Version strings and identifiers
            r'^\d+\.\d+',
            r'^v\d+',
            r'version.*\d+',
            
            # All zeros, ones or simple patterns
            r'^0+$',
            r'^1+$',
            r'^(abc|123|xyz|test){3,}$',
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' if string.count('-') == 4 and len(string) == 36 and 'test' in string_lower else None,
            
            # Common configuration keys that aren't secrets
            r'^(true|false|enabled|disabled|yes|no)$',
            r'^\d+$',  # Pure numbers
            r'^[a-z]+$' if len(string) < 8 else None,  # Short all-lowercase strings
            
            # File paths and system strings
            r'^[\\/]',  # Starts with path separator
            r'\\x[0-9a-f]{2}',  # Hex escape sequences
            r'%[0-9a-f]{2}',  # URL encoding
            
            # Common Android/mobile development false positives
            r'android.*',
            r'build.*config',
            r'manifest.*',
            r'application.*id',
            r'package.*name',
            
            # Base64 patterns that are likely not secrets
            r'^data:image',  # Data URLs
            r'iVBORw0KGgo',  # PNG header in base64
            r'/9j/',  # JPEG header in base64
        ]
        
        for pattern in false_positives:
            if pattern and re.search(pattern, string_lower):
                return True
        
        # Additional heuristic checks
        # Skip very short strings for high-entropy patterns
        if len(string) < 16 and any(x in string_lower for x in ['entropy', 'random', 'base64']):
            return True
            
        # Skip strings that are mostly numbers
        if len(string) > 8 and sum(c.isdigit() for c in string) / len(string) > 0.8:
            return True
            
        # Skip strings with too many special characters (likely encoded data, not keys)
        special_chars = sum(1 for c in string if not c.isalnum())
        if len(string) > 20 and special_chars / len(string) > 0.3:
            return True
        
        return False
    
    def _assess_weak_cryptography(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for weak cryptographic algorithms"""
        findings = []
        
        # Check API calls for weak crypto usage
        api_results = analysis_results.get('api_invocation', {})
        if hasattr(api_results, 'to_dict'):
            api_data = api_results.to_dict()
        else:
            api_data = api_results
        
        if not isinstance(api_data, dict):
            return findings
        
        weak_crypto_evidence = []
        api_calls = api_data.get('api_calls', [])
        
        for call in api_calls:
            if isinstance(call, dict):
                api_name = call.get('called_class', '') + '.' + call.get('called_method', '')
                
                # Check for weak algorithms
                weak_algorithms = ['DES', 'RC4', 'MD5', 'SHA1']
                for weak_algo in weak_algorithms:
                    if weak_algo.lower() in api_name.lower():
                        weak_crypto_evidence.append(f"Weak algorithm usage: {api_name}")
                        break
        
        # Also check strings for algorithm names
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
            all_strings = []
            for key in ['emails', 'urls', 'domains']:
                strings = string_data.get(key, [])
                if isinstance(strings, list):
                    all_strings.extend(strings)
            
            for string in all_strings:
                if isinstance(string, str):
                    for weak_algo in ['DES', 'RC4', 'MD5', 'SHA1']:
                        if weak_algo in string.upper():
                            weak_crypto_evidence.append(f"Weak algorithm reference: {string[:50]}...")
                            break
        
        if weak_crypto_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Weak Cryptographic Algorithms Detected",
                description="Usage of weak or deprecated cryptographic algorithms that may be vulnerable to attacks.",
                evidence=weak_crypto_evidence,
                recommendations=[
                    "Replace weak algorithms with stronger alternatives (AES, SHA-256, etc.)",
                    "Use Android's recommended cryptographic libraries",
                    "Implement proper key management",
                    "Follow current cryptographic best practices",
                    "Regularly update cryptographic implementations"
                ]
            ))
        
        return findings
    
    def _assess_sensitive_permissions(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess permissions that may lead to sensitive data access"""
        findings = []
        
        # Get permission analysis results
        permission_results = analysis_results.get('permission_analysis', {})
        if hasattr(permission_results, 'to_dict'):
            permission_data = permission_results.to_dict()
        else:
            permission_data = permission_results
        
        if not isinstance(permission_data, dict):
            return findings
        
        all_permissions = permission_data.get('all_permissions', [])
        sensitive_found = []
        
        for permission in all_permissions:
            if isinstance(permission, str):
                for sensitive_perm in self.sensitive_permissions:
                    if sensitive_perm in permission:
                        sensitive_found.append(permission)
                        break
        
        if sensitive_found:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Sensitive Data Access Permissions",
                description="Application requests permissions that provide access to sensitive user data.",
                evidence=[f"Permission: {perm}" for perm in sensitive_found],
                recommendations=[
                    "Ensure sensitive data is encrypted before storage",
                    "Implement proper data retention policies",
                    "Use runtime permissions and explain data usage to users",
                    "Minimize data collection to what's necessary for functionality",
                    "Implement secure data transmission (HTTPS, certificate pinning)",
                    "Follow platform guidelines for handling sensitive data"
                ]
            ))
        
        return findings