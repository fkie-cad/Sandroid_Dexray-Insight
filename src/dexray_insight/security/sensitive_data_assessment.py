#!/usr/bin/env python3
"""OWASP A03:2021 - Sensitive Data Exposure security assessment with 54+ secret patterns."""

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

import logging
import re
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment
from .evidence import WEAK_CRYPTO_TOKENS
from .evidence import collect_weak_crypto_evidence
from .evidence import matches_algorithm_token
from .secret_validation import SecretValidator


@register_assessment("sensitive_data")
class SensitiveDataAssessment(BaseSecurityAssessment):
    """OWASP A02:2021 - Cryptographic Failures / Sensitive Data Exposure assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize SensitiveDataAssessment with comprehensive configuration.

        Refactored to use single-responsibility functions following SOLID principles.
        Maintains exact same behavior as original while improving maintainability.

        Each section is now handled by a dedicated function with single responsibility:
        - Basic configuration and logging
        - Pattern enablement configuration
        - Threshold and context configuration
        - PII pattern compilation
        - Critical security pattern setup
        - High/medium severity pattern setup
        - Low severity and context pattern setup
        - Legacy compatibility setup
        """
        super().__init__(config)

        # Use refactored single-responsibility functions for each configuration section
        self._initialize_basic_configuration(config)
        self._setup_pattern_enablement(config)
        self._initialize_threshold_configuration(config)
        self._compile_pii_patterns()
        self._setup_critical_security_patterns()
        self._setup_high_medium_severity_patterns()
        self._setup_low_severity_context_patterns()
        self._setup_structural_client_patterns()
        self._setup_legacy_compatibility()

        # Assign detection_patterns for strategy pattern usage
        self.detection_patterns = getattr(self, "key_detection_patterns", {})

    def _initialize_basic_configuration(self, config: dict[str, Any]):
        """Initialize basic class configuration and logging.

        Single Responsibility: Set up core class attributes, logging, and OWASP category only.
        """
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A02:2021-Cryptographic Failures"

        self.pii_patterns = config.get("pii_patterns", ["email", "phone", "ssn", "credit_card"])
        self.crypto_keys_check = config.get("crypto_keys_check", True)

    def _setup_pattern_enablement(self, config: dict[str, Any]):
        """Configure which detection patterns are enabled.

        Single Responsibility: Handle pattern enablement configuration only.
        """
        # Enhanced key detection configuration
        self.key_detection_config = config.get("key_detection", {})
        self.key_detection_enabled = self.key_detection_config.get("enabled", True)

        # Pattern enablement
        pattern_config = self.key_detection_config.get("patterns", {})
        self.enabled_patterns = {
            "pem_keys": pattern_config.get("pem_keys", True),
            "ssh_keys": pattern_config.get("ssh_keys", True),
            "jwt_tokens": pattern_config.get("jwt_tokens", True),
            "api_keys": pattern_config.get("api_keys", True),
            "base64_keys": pattern_config.get("base64_keys", True),
            "hex_keys": pattern_config.get("hex_keys", True),
            "database_connections": pattern_config.get("database_connections", True),
            "high_entropy_strings": pattern_config.get("high_entropy_strings", True),
        }

    def _initialize_threshold_configuration(self, config: dict[str, Any]):
        """Set up entropy thresholds, length filters, and context detection.

        Single Responsibility: Configure detection thresholds and context settings only.
        """
        # Entropy thresholds - uses self.key_detection_config set by pattern enablement
        entropy_config = getattr(self, "key_detection_config", {}).get("entropy_thresholds", {})
        self.entropy_thresholds = {
            "min_base64_entropy": entropy_config.get("min_base64_entropy", 4.0),
            "min_hex_entropy": entropy_config.get("min_hex_entropy", 3.5),
            "min_generic_entropy": entropy_config.get("min_generic_entropy", 5.0),
        }

        # Length filters
        length_config = getattr(self, "key_detection_config", {}).get("length_filters", {})
        self.length_filters = {
            "min_key_length": length_config.get("min_key_length", 16),
            "max_key_length": length_config.get("max_key_length", 512),
        }

        # Context detection settings
        context_config = getattr(self, "key_detection_config", {}).get("context_detection", {})
        self.context_detection_enabled = context_config.get("enabled", True)
        self.context_strict_mode = context_config.get("strict_mode", False)

    def _compile_pii_patterns(self):
        """Compile PII detection regex patterns.

        Single Responsibility: Create PII regex patterns only.
        """
        # PII detection patterns
        self.pii_regex_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            "ssn": r"\b\d{3}-?\d{2}-?\d{4}\b",
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        }

    def _setup_critical_security_patterns(self):
        """Set up CRITICAL severity security detection patterns.

        Single Responsibility: Define critical security patterns only.
        """
        self.key_detection_patterns = {
            # CRITICAL SEVERITY PATTERNS
            # Private Keys - Enhanced patterns from secret-finder
            "pem_private_key": {
                "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY(?: BLOCK)?-----",
                "description": "Private Key",
                "severity": "CRITICAL",
            },
            "ssh_private_key": {
                "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+/\s=]+-----END OPENSSH PRIVATE KEY-----",  # pragma: allowlist secret
                "description": "SSH private key",
                "severity": "CRITICAL",
            },
            # AWS Credentials - Enhanced from secret-finder
            "aws_access_key": {
                # Case-sensitive with word boundaries: AWS key-id prefixes are always
                # uppercase. Without case_sensitive, re.IGNORECASE let the "AIDA" prefix
                # match lowercase identifiers such as "aidAdRendererContainer" (Unity Ads
                # event constants), producing the fake "10 CRITICAL secrets" finding.
                "pattern": r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
                "description": "AWS Access Key ID",
                "severity": "CRITICAL",
                "case_sensitive": True,
            },
            "aws_secret_key": {
                "pattern": r'(?i)aws(?:.{0,20})?(?:secret|key|token).{0,20}?[\'"]([A-Za-z0-9/+=]{40})[\'"]',
                "description": "AWS Secret Access Key",
                "severity": "CRITICAL",
            },
            # GitHub Tokens - Enhanced patterns
            "github_token": {"pattern": r"ghp_[0-9a-zA-Z]{36}", "description": "GitHub Token", "severity": "CRITICAL"},
            "github_fine_grained_token": {
                "pattern": r"github_pat_[0-9a-zA-Z_]{82}",
                "description": "GitHub Fine-Grained Token",
                "severity": "CRITICAL",
            },
            "github_token_in_url": {
                "pattern": r"[a-zA-Z0-9_-]*:([a-zA-Z0-9_\-]+)@github\.com",
                "description": "GitHub Token in URL",
                "severity": "CRITICAL",
            },
            # Google Credentials - Enhanced patterns
            "google_oauth_token": {
                "pattern": r"ya29\.[0-9A-Za-z\-_]+",
                "description": "Google OAuth Token",
                "severity": "CRITICAL",
            },
            "google_service_account": {
                "pattern": r'"type":\s*"service_account"',
                "description": "Google (GCP) Service Account",
                "severity": "CRITICAL",
            },
            "google_api_key_aiza": {
                # Fixed character class: the previous r"[0-9A-Za-z\\-_]" contained a
                # literal backslash followed by the range "\"-"_", which excluded the
                # hyphen that real AIza keys contain, dropping valid keys.
                "pattern": r"AIza[0-9A-Za-z_-]{35}",
                "description": "Google API Key (AIza format)",
                "severity": "CRITICAL",
                "context_required": ["api", "key", "google"],  # Reduce false positives
            },
            "google_maps_api_key": {
                "pattern": r"(?i)(?:maps?|geo|location).*AIza[0-9A-Za-z\-_]{35}",
                "description": "Google Maps API Key",
                "severity": "CRITICAL",
            },
            # Firebase & Other Critical
            "firebase_cloud_messaging_key": {
                "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
                "description": "Firebase Cloud Messaging Key",
                "severity": "CRITICAL",
            },
            "firebase_realtime_db_key": {
                "pattern": r"(?i)firebase.*['\"]([a-zA-Z0-9]{20,})['\"]",
                "description": "Firebase Realtime Database Key",
                "severity": "CRITICAL",
                "min_entropy": 4.0,
            },
            "aws_amplify_key": {
                "pattern": r"(?i)amplify.*['\"]([a-zA-Z0-9+/=]{40,})['\"]",
                "description": "AWS Amplify API Key",
                "severity": "CRITICAL",
                "min_entropy": 4.5,
            },
            "password_in_url": {
                "pattern": r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:([^/\s:@]{3,20})@.{1,100}["\'\s]',
                "description": "Password in URL",
                "severity": "CRITICAL",
            },
        }

    def _setup_high_medium_severity_patterns(self):
        """Set up HIGH and MEDIUM severity security detection patterns.

        Single Responsibility: Define high and medium severity patterns only.
        """
        if not hasattr(self, "key_detection_patterns"):
            self.key_detection_patterns = {}
        self._setup_high_severity_patterns()
        self._setup_medium_severity_patterns()

    def _setup_high_severity_patterns(self):
        """Set up HIGH severity security detection patterns.

        Single Responsibility: Define high severity patterns only.
        """
        # HIGH SEVERITY PATTERNS
        high_patterns = {
            # Generic Password/API Key Patterns - Enhanced with context
            "generic_password": {
                "pattern": r'(?i)\b(?:password|pass|pwd|passwd)\b\s*[:=]\s*[\'"]?([^\s\'"/\\,;<>]{8,})[\'"]?',
                "description": "Password",
                "severity": "HIGH",
                "context_required": ["password", "pass", "pwd", "auth"],
                "min_entropy": 3.0,  # Require some randomness
            },
            "generic_api_key": {
                "pattern": r'(?i)\b(?:api_key|apikey|api-key|access_key|access-key|secret_key|secret-key)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-_.]{20,})[\'"]?',
                "description": "Generic API Key",
                "severity": "HIGH",
                "min_entropy": 4.0,  # API keys should have good entropy
            },
            "generic_secret": {
                "pattern": r'(?i)\bsecret\b.*[\'"]([0-9a-zA-Z]{32,45})[\'"]',
                "description": "Generic Secret",
                "severity": "HIGH",
                "min_entropy": 4.5,  # Secrets should be random
            },
            # JWT tokens
            "jwt_token": {
                "pattern": r"ey[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*",
                "description": "JWT Token",
                "severity": "HIGH",
            },
            # Service-Specific High Severity
            "azure_client_secret": {
                "pattern": r'(?i)\b(?:azure_client_secret|client_secret)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-~_\\.]{30,})[\'"]?',
                "description": "Azure Client Secret",
                "severity": "HIGH",
            },
            "heroku_api_key": {
                "pattern": r'(?i)\b(?:heroku_api_key|heroku-api-key)\b\s*[:=]\s*[\'"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})[\'"]?',
                "description": "Heroku API Key",
                "severity": "HIGH",
            },
            "stripe_api_key": {
                "pattern": r"(?:sk|pk)_live_[0-9a-zA-Z]{24}",
                "description": "Stripe API Key",
                "severity": "HIGH",
            },
            "discord_bot_token": {
                "pattern": r"[M-Z][a-zA-Z0-9\-_]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,}",
                "description": "Discord Bot Token",
                "severity": "HIGH",
            },
            "gitlab_personal_token": {
                "pattern": r"glpat-[0-9a-zA-Z\-_]{20}",
                "description": "GitLab Personal Token",
                "severity": "HIGH",
            },
            "amazon_mws_auth_token": {
                "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "description": "Amazon MWS Auth Token",
                "severity": "HIGH",
            },
            "facebook_access_token": {
                "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
                "description": "Facebook Access Token",
                "severity": "HIGH",
            },
            "facebook_oauth_secret": {
                "pattern": r'(?i)facebook.*[\'"]([0-9a-f]{32})[\'"]',
                "description": "Facebook OAuth Secret",
                "severity": "HIGH",
            },
            "mailchimp_api_key": {
                "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",
                "description": "MailChimp API Key",
                "severity": "HIGH",
            },
            "mailgun_api_key": {
                "pattern": r"key-[0-9a-zA-Z]{32}",
                "description": "Mailgun API Key",
                "severity": "HIGH",
            },
            "picatic_api_key": {
                "pattern": r"sk_live_[0-9a-z]{32}",
                "description": "Picatic API Key",
                "severity": "HIGH",
            },
            "square_access_token": {
                "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}",
                "description": "Square Access Token",
                "severity": "HIGH",
            },
            "square_oauth_secret": {
                "pattern": r"sq0csp-[0-9A-Za-z\-_]{43}",
                "description": "Square OAuth Secret",
                "severity": "HIGH",
            },
            "twitter_access_token": {
                "pattern": r"(?i)\btwitter\b.*([1-9][0-9]+-[0-9a-zA-Z]{40})",
                "description": "Twitter Access Token",
                "severity": "HIGH",
            },
            "twitter_oauth_secret": {
                "pattern": r'(?i)\btwitter\b.*[\'"]([0-9a-zA-Z]{35,44})[\'"]',
                "description": "Twitter OAuth Secret",
                "severity": "HIGH",
            },
            "authorization_basic": {
                "pattern": r"basic [a-zA-Z0-9=:_\+\/-]{5,100}",
                "description": "Authorization Basic",
                "severity": "HIGH",
            },
            "authorization_bearer": {
                "pattern": r"bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}",
                "description": "Authorization Bearer",
                "severity": "HIGH",
            },
            "slack_token": {
                "pattern": r"xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
                "description": "Slack Token",
                "severity": "HIGH",
            },
        }
        self.key_detection_patterns.update(high_patterns)

    def _setup_medium_severity_patterns(self):
        """Set up MEDIUM severity security detection patterns.

        Single Responsibility: Define medium severity patterns only.
        """
        # MEDIUM SEVERITY PATTERNS
        medium_patterns = {
            "slack_token_legacy": {
                "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
                "description": "Slack Token (Legacy)",
                "severity": "MEDIUM",
            },
            # Database Connection URIs
            "mongodb_uri": {
                "pattern": r"mongodb(?:\+srv)?:\/\/[^\s]+",
                "description": "MongoDB URI",
                "severity": "MEDIUM",
            },
            "postgresql_uri": {
                "pattern": r"postgres(?:ql)?:\/\/[^\s]+",
                "description": "PostgreSQL URI",
                "severity": "MEDIUM",
            },
            "mysql_uri": {"pattern": r"mysql:\/\/[^\s]+", "description": "MySQL URI", "severity": "MEDIUM"},
            "redis_uri": {"pattern": r"redis:\/\/[^\s]+", "description": "Redis URI", "severity": "MEDIUM"},
            "cloudinary_url": {
                "pattern": r"cloudinary://[^\s]+",
                "description": "Cloudinary URL",
                "severity": "MEDIUM",
            },
            "firebase_url": {
                "pattern": r'[^"\']+\.firebaseio\.com',
                "description": "Firebase URL",
                "severity": "MEDIUM",
            },
            "slack_webhook_url": {
                "pattern": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
                "description": "Slack Webhook URL",
                "severity": "MEDIUM",
            },
            # SSH Public Keys and Certificates
            "ssh_public_key": {
                "pattern": r"ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/]+=*",
                "description": "SSH public key",
                "severity": "MEDIUM",
            },
            "pem_certificate": {
                "pattern": r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/\s=]+-----END CERTIFICATE-----",
                "description": "PEM-formatted certificate",
                "severity": "MEDIUM",
            },
            # Hex encoded keys
            "hex_key_256": {"pattern": r"[a-fA-F0-9]{64}", "description": "256-bit hex key", "severity": "MEDIUM"},
            "hex_key_128": {"pattern": r"[a-fA-F0-9]{32}", "description": "128-bit hex key", "severity": "MEDIUM"},
            # Smali const-string patterns for API keys
            "smali_const_string_api_key": {
                "pattern": r'const-string\s+v\d+,\s*"([^"]{20,})"',
                "description": "Smali const-string API key pattern",
                "severity": "MEDIUM",
                "min_entropy": 4.0,
                "context_required": ["key", "token", "secret", "api"],
            },
            # Android-specific API keys
            "android_build_config_key": {
                "pattern": r'BuildConfig\.[A-Z_]+\s*=\s*[\'"]([a-zA-Z0-9]{20,})[\'"]',
                "description": "Android BuildConfig API Key",
                "severity": "MEDIUM",
                "min_entropy": 4.0,
            },
            "android_resources_api_key": {
                "pattern": r'R\.string\.[a-z_]*(?:key|token|secret|api)[a-z_]*',
                "description": "Android Resources API Key Reference",
                "severity": "LOW",  # Just a reference, not the actual key
            },
        }
        self.key_detection_patterns.update(medium_patterns)

    def _setup_low_severity_context_patterns(self):
        """Set up LOW severity patterns and context keywords.

        Single Responsibility: Define low severity patterns and context detection only.
        """
        # LOW SEVERITY PATTERNS
        low_patterns = {
            "jenkins_api_token": {"pattern": r"11[0-9a-f]{32}", "description": "Jenkins API Token", "severity": "LOW"},
            "stripe_restricted_key": {
                "pattern": r"rk_live_[0-9a-zA-Z]{24}",
                "description": "Stripe Restricted Key",
                "severity": "LOW",
            },
            "paypal_braintree_token": {
                "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
                "description": "PayPal Braintree Token",
                "severity": "LOW",
            },
            "google_captcha_key": {
                "pattern": r"6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
                "description": "Google Captcha Key",
                "severity": "LOW",
            },
            "s3_bucket_url": {
                "pattern": r"[a-zA-Z0-9._-]+\.s3\.amazonaws\.com",
                "description": "S3 Bucket URL",
                "severity": "LOW",
            },
            # Base64 encoded keys (high entropy)
            "base64_key_long": {
                "pattern": r"[A-Za-z0-9+/]{64,}={0,2}",
                "description": "Long Base64 encoded string (potential key)",
                "severity": "LOW",
                "min_entropy": 4.5,
            },
            "base64_key_medium": {
                "pattern": r"[A-Za-z0-9+/]{32,63}={0,2}",
                "description": "Medium Base64 encoded string (potential key)",
                "severity": "LOW",
                "min_entropy": 4.0,
            },
            # Generic high-entropy strings
            "high_entropy_string": {
                "pattern": r"[A-Za-z0-9+/=]{20,}",
                "description": "High entropy string (potential key)",
                "severity": "LOW",
                "min_entropy": 5.0,
                "max_length": 512,
            },
        }

        # Add to existing patterns - initialize if doesn't exist
        if not hasattr(self, "key_detection_patterns"):
            self.key_detection_patterns = {}
        self.key_detection_patterns.update(low_patterns)

        # Context keywords that increase suspicion level
        self.key_context_keywords = {
            "high_risk": ["password", "secret", "private", "key", "token", "credential", "auth"],
            "crypto": ["aes", "rsa", "des", "rc4", "encrypt", "decrypt", "cipher", "crypto"],
            "api": ["api", "token", "bearer", "oauth", "jwt", "auth"],
            "database": ["db", "database", "connection", "conn", "sql", "mysql", "postgres"],
        }

    def _setup_structural_client_patterns(self):
        """Set up structural client-credential patterns (PR-5).

        Single Responsibility: Define distinctive prefix/format patterns for real
        client keys that were previously MISSED (Branch, AdMob, Crashlytics). These
        are surfaced at LOW because they are client-side keys (safe by design); the
        SecretValidator reclassifies them via the known-safe-credentials registry.
        """
        if not hasattr(self, "key_detection_patterns"):
            self.key_detection_patterns = {}
        structural_patterns = {
            # Branch.io client key: shipped in the app, public by design.
            "branch_io_key": {
                "pattern": r"\bkey_live_[0-9A-Za-z]{32}\b",
                "description": "Branch.io Live Key (client-side)",
                "severity": "LOW",
            },
            # Google AdMob application id: public client identifier.
            "admob_app_id": {
                "pattern": r"\bca-app-pub-\d{16}~\d{10}\b",
                "description": "Google AdMob App ID (client-side)",
                "severity": "LOW",
            },
            # Crashlytics / Fabric API key: 40-hex, anchored on a crashlytics/fabric
            # co-location marker to avoid matching arbitrary SHA-1 hashes. The key
            # itself is captured in group(1).
            "crashlytics_api_key": {
                "pattern": r"(?i)(?:crashlytics|fabric).{0,40}?\b([0-9a-fA-F]{40})\b",
                "description": "Crashlytics/Fabric API Key (client-side)",
                "severity": "LOW",
            },
        }
        self.key_detection_patterns.update(structural_patterns)

    def _setup_legacy_compatibility(self):
        """Maintain backward compatibility with legacy patterns and permissions.

        Single Responsibility: Set up legacy compatibility patterns and sensitive permissions only.
        """
        # Legacy crypto patterns (kept for backward compatibility)
        self.crypto_patterns = [
            "DES",
            "RC4",
            "MD5",
            "SHA1",
            "password",
            "passwd",
            "pwd",
            "secret",
            "key",
            "token",
            "api_key",
            "private_key",
            "public_key",
            "certificate",
            "keystore",
        ]

        # Permissions that may indicate sensitive data access
        self.sensitive_permissions = [
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "READ_SMS",
            "RECEIVE_SMS",
            "READ_PHONE_STATE",
            "READ_PHONE_NUMBERS",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "ACCESS_BACKGROUND_LOCATION",
            "CAMERA",
            "RECORD_AUDIO",
            "BODY_SENSORS",
            "READ_CALENDAR",
            "WRITE_CALENDAR",
        ]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Assess for sensitive data exposure vulnerabilities.

        Args:
            analysis_results: Combined results from all analysis modules

        Returns:
            List of security findings related to sensitive data exposure
        """
        findings: list[SecurityFinding] = []

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

    def _assess_weak_cryptography(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for weak cryptographic algorithms.

        Algorithm tokens are matched only as a ``getInstance`` argument or as a
        whole word (``\\bDES\\b``), never as a substring. This removes the former
        false positives where ``des`` matched ``Descriptor`` / ``desktop`` and
        ``adDescriptor.bids``.
        """
        findings: list[SecurityFinding] = []

        api_results = analysis_results.get("api_invocation", {})
        api_data = api_results.to_dict() if hasattr(api_results, "to_dict") else api_results
        if not isinstance(api_data, dict):
            return findings

        # Gather decompiled strings (full set, not just emails/urls/domains).
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", []) if isinstance(string_data, dict) else []
        if not isinstance(all_strings, list):
            all_strings = []

        # Shared, evidence-required collector (crypto_usage + whole-word/arg on strings).
        weak_crypto_evidence = collect_weak_crypto_evidence(analysis_results, all_strings)

        # API calls: only flag when a weak token appears as a WHOLE WORD in the
        # class/method name (e.g. Ldes/...;), never as a substring of Descriptor.
        for call in api_data.get("api_calls", []):
            if isinstance(call, dict):
                api_name = f"{call.get('called_class', '')}.{call.get('called_method', '')}"
                if any(matches_algorithm_token(api_name, token) for token in WEAK_CRYPTO_TOKENS):
                    weak_crypto_evidence.append(f"Weak algorithm usage: {api_name}")

        if weak_crypto_evidence:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.HIGH,
                    title="Weak Cryptographic Algorithms Detected",
                    description="Usage of weak or deprecated cryptographic algorithms that may be vulnerable to attacks.",
                    evidence=weak_crypto_evidence,
                    confidence=0.7,
                    recommendations=[
                        "Replace weak algorithms with stronger alternatives (AES, SHA-256, etc.)",
                        "Use Android's recommended cryptographic libraries",
                        "Implement proper key management",
                        "Follow current cryptographic best practices",
                        "Regularly update cryptographic implementations",
                    ],
                )
            )

        return findings

    def _assess_sensitive_permissions(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess permissions that may lead to sensitive data access."""
        findings: list[SecurityFinding] = []

        # Get permission analysis results
        permission_results = analysis_results.get("permission_analysis", {})
        permission_data = permission_results.to_dict() if hasattr(permission_results, "to_dict") else permission_results

        if not isinstance(permission_data, dict):
            return findings

        all_permissions = permission_data.get("all_permissions", [])
        sensitive_found = []

        for permission in all_permissions:
            if isinstance(permission, str):
                for sensitive_perm in self.sensitive_permissions:
                    if sensitive_perm in permission:
                        sensitive_found.append(permission)
                        break

        if sensitive_found:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="Sensitive Data Access Permissions",
                    description="Application requests permissions that provide access to sensitive user data.",
                    evidence=sensitive_found,
                    recommendations=[
                        "Review if all permissions are necessary for app functionality",
                        "Implement runtime permission requests where possible",
                        "Provide clear explanations for why permissions are needed",
                        "Consider alternative approaches that require fewer permissions",
                    ],
                )
            )

        return findings

    def _assess_pii_exposure(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for PII exposure in strings."""
        findings: list[SecurityFinding] = []

        # Get string analysis results
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results

        if not isinstance(string_data, dict):
            return findings

        # Collect all strings for analysis
        all_strings = []
        for key in ["emails", "urls", "domains"]:
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
                    if isinstance(string, str) and re.search(pattern, string):
                        matches.append(string[:50] + "..." if len(string) > 50 else string)

                if matches:
                    pii_found[pii_type] = matches

        # Also check emails from string analysis results
        emails = string_data.get("emails", [])
        if emails:
            pii_found["emails_detected"] = [email[:30] + "..." for email in emails[:5]]

        if pii_found:
            evidence = []
            for pii_type, matches in pii_found.items():
                evidence.append(f"{pii_type.upper()}: {len(matches)} instances found")
                evidence.extend([f"  - {match}" for match in matches[:3]])  # Show first 3

            findings.append(
                SecurityFinding(
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
                        "Ensure compliance with privacy regulations (GDPR, CCPA, etc.)",
                    ],
                )
            )

        return findings

    def _assess_crypto_keys_exposure(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess for exposed cryptographic keys and secrets using comprehensive detection.

        Refactored to use Strategy Pattern with focused responsibilities:
        - StringCollectionStrategy: Gather strings from various sources
        - DeepAnalysisStrategy: Extract from XML/Smali files
        - PatternDetectionStrategy: Find secrets using patterns
        - ResultClassificationStrategy: Organize findings by severity
        - FindingGenerationStrategy: Create SecurityFinding objects

        Single Responsibility: Orchestrate the secret detection workflow by delegating
        to specialized strategy classes.
        """
        # Initialize strategies for different aspects of secret detection
        string_collector = StringCollectionStrategy(self.logger)
        deep_analyzer = DeepAnalysisStrategy(self.logger)

        # PR-5: build the precision/recall validator from this assessment's threshold
        # configuration so the dexray.yaml knobs reach the active detection path.
        validator = SecretValidator(
            entropy_thresholds=self.entropy_thresholds,
            length_filters=self.length_filters,
            context_detection_enabled=self.context_detection_enabled,
            context_strict_mode=self.context_strict_mode,
            key_detection_config=self.key_detection_config,
            logger=self.logger,
        )
        pattern_detector = PatternDetectionStrategy(self.detection_patterns, self.logger, validator=validator)
        result_classifier = ResultClassificationStrategy()
        finding_generator = FindingGenerationStrategy(self.owasp_category)

        # Execute secret detection workflow using strategies
        all_strings = string_collector.collect_strings(analysis_results)
        enhanced_strings = deep_analyzer.extract_deep_strings(analysis_results, all_strings)
        detected_secrets = pattern_detector.detect_secrets(enhanced_strings)
        classified_results = result_classifier.classify_by_severity(detected_secrets)

        return finding_generator.generate_security_findings(classified_results)


class StringCollectionStrategy:
    """
    Strategy for collecting strings from various analysis sources.

    This strategy implements the first phase of secret detection by gathering
    strings from multiple analysis sources including string analysis results,
    Android properties, and raw strings.

    Responsibilities:
    - Extract strings from string analysis module results
    - Collect Android properties and system configuration strings
    - Gather raw strings from multiple sources
    - Add location metadata to each collected string

    Design Pattern: Strategy Pattern (part of secret detection workflow)
    SOLID Principles: Single Responsibility (only handles string collection)
    """

    def __init__(self, logger):
        """Initialize the string collector with logger."""
        self.logger = logger

    def collect_strings(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect strings with location information from analysis results.

        This method systematically extracts strings from various analysis sources
        and enriches them with location metadata for later pattern detection.

        Args:
            analysis_results: Dictionary containing results from various analysis modules
                            Expected keys: 'string_analysis' (primary source)

        Returns:
            List of dictionaries, each containing:
            - 'value': The string value to analyze
            - 'location': Human-readable source location
            - 'file_path': File path if available (optional)
            - 'line_number': Line number if available (optional)

        Raises:
            None: Method handles all exceptions gracefully and returns partial results

        Single Responsibility: Gather strings from all available sources.
        """
        all_strings_with_location: list[dict[str, Any]] = []

        string_data = self._resolve_string_data(analysis_results)

        if not isinstance(string_data, dict):
            return all_strings_with_location

        # B1a: Collapse the multiple string sources into ONE de-duplicated pass.
        # The same underlying strings were previously gathered up to three times - via
        # the "all_strings" field, the string module's all_strings attribute, and the
        # raw strings collector - which made the downstream pattern scan run over
        # identical values 2-3x. Every collector is still consulted (each may
        # contribute genuinely unique values), but only the FIRST occurrence of each
        # distinct string value is retained. Duplicate string values can only ever
        # yield identical detections (which are de-duplicated again in
        # ResultClassificationStrategy), so dropping them here does not change the set
        # of detected secrets or any reported count - it only avoids redundant scanning.
        seen_values: set[str] = set()

        def _add_unique(collected: list[dict[str, Any]]) -> None:
            for item in collected:
                value = item.get("value", "")
                dedup_key = value if isinstance(value, str) else str(value)
                if dedup_key in seen_values:
                    continue
                seen_values.add(dedup_key)
                all_strings_with_location.append(item)

        _add_unique(self._collect_category_location_strings(string_data))
        _add_unique(self._collect_all_strings_field(string_data))
        _add_unique(self._collect_module_all_strings(analysis_results))
        _add_unique(self._collect_android_property_strings(string_data))
        _add_unique(self._collect_raw_strings(string_data))

        self.logger.debug(f"Collected {len(all_strings_with_location)} unique strings for secret scanning")

        return all_strings_with_location

    def _resolve_string_data(self, analysis_results: dict[str, Any]) -> Any:
        """Resolve string analysis data from direct or in_depth_analysis locations."""
        # Get string analysis results - check both direct and in_depth_analysis locations
        string_results = analysis_results.get("string_analysis", {})
        if hasattr(string_results, "to_dict"):
            return string_results.to_dict()
        elif string_results:
            return string_results
        # Fallback: check in_depth_analysis for string data
        in_depth = analysis_results.get("in_depth_analysis", {})
        in_depth_data = in_depth.to_dict() if hasattr(in_depth, "to_dict") else in_depth

        # Map in_depth_analysis string fields to expected format
        return {
            "emails": in_depth_data.get("strings_emails", []),
            "ip_addresses": in_depth_data.get("strings_ip", []),
            "urls": in_depth_data.get("strings_urls", []),
            "domains": in_depth_data.get("strings_domain", []),
        }

    def _collect_category_location_strings(self, string_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect strings from all standard string analysis categories."""
        collected = []
        # From string analysis results - include ALL string categories
        string_categories = ["emails", "urls", "domains", "ip_addresses", "interesting_strings", "filtered_strings"]
        for key in string_categories:
            strings = string_data.get(key, [])
            if isinstance(strings, list):
                for string in strings:
                    collected.append(
                        {
                            "value": string,
                            "location": f"String analysis ({key})",
                            "file_path": None,
                            "line_number": None,
                        }
                    )
        return collected

    def _collect_all_strings_field(self, string_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect strings from the all_strings field of string data."""
        collected = []
        # CRITICAL: Also get ALL strings from string analysis module for secret detection
        # This ensures we include XML-extracted strings that may contain API keys
        if "all_strings" in string_data:
            all_strings_list = string_data.get("all_strings", [])
            if isinstance(all_strings_list, list):
                for string in all_strings_list:
                    collected.append(
                        {
                            "value": str(string),
                            "location": "All extracted strings (including XML)",
                            "file_path": None,
                            "line_number": None,
                        }
                    )
                self.logger.debug(f"Added {len(all_strings_list)} strings from all_strings field")
        return collected

    def _collect_module_all_strings(self, analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect all_strings from the string analysis module result if available."""
        collected = []
        # Fallback: If string_analysis module result is available directly, get all_strings from it
        string_module_result = analysis_results.get("string_analysis")
        if string_module_result and hasattr(string_module_result, "all_strings"):
            all_strings_from_module = getattr(string_module_result, "all_strings", [])
            if isinstance(all_strings_from_module, list):
                for string in all_strings_from_module:
                    collected.append(
                        {
                            "value": str(string),
                            "location": "String analysis module (all_strings)",
                            "file_path": None,
                            "line_number": None,
                        }
                    )
                self.logger.debug(f"Added {len(all_strings_from_module)} strings from string module all_strings")
        return collected

    def _collect_android_property_strings(self, string_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect strings from Android properties keys and values."""
        collected = []
        # From Android properties
        android_props = string_data.get("android_properties", {})
        if isinstance(android_props, dict):
            for prop_key, prop_value in android_props.items():
                collected.append(
                    {"value": prop_key, "location": "Android properties", "file_path": None, "line_number": None}
                )
                if isinstance(prop_value, str):
                    collected.append(
                        {"value": prop_value, "location": "Android properties", "file_path": None, "line_number": None}
                    )
        return collected

    def _collect_raw_strings(self, string_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect raw strings from the string analysis all_strings field."""
        collected = []
        # Get raw strings from the string analysis if available
        raw_strings = string_data.get("all_strings", [])
        if isinstance(raw_strings, list):
            for string in raw_strings:
                collected.append(
                    {"value": string, "location": "Raw strings", "file_path": None, "line_number": None}
                )
        return collected


class DeepAnalysisStrategy:
    """
    Strategy for extracting strings from deep analysis sources (XML, Smali, DEX).

    This strategy implements enhanced string extraction by leveraging deep analysis
    artifacts like Androguard objects, DEX files, XML resources, and Smali code.
    It only operates when deep analysis mode is enabled.

    Responsibilities:
    - Determine analysis mode (fast vs deep)
    - Extract strings from DEX objects using Androguard
    - Extract strings from XML resources (delegates to existing methods)
    - Extract strings from Smali code (delegates to existing methods)
    - Enrich existing string collection with deep analysis findings

    Design Pattern: Strategy Pattern (second phase of secret detection workflow)
    SOLID Principles: Single Responsibility (only handles deep string extraction)
    """

    def __init__(self, logger):
        """Initialize the deep string extractor with logger."""
        self.logger = logger

    def extract_deep_strings(
        self, analysis_results: dict[str, Any], existing_strings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Extract strings from deep analysis sources like XML and Smali files.

        This method attempts to extract additional strings from deep analysis artifacts
        if they are available. It operates in different modes based on analysis depth:
        - DEEP mode: Extracts from DEX, XML, and Smali sources
        - FAST mode: Returns existing strings unchanged (limited sources)

        Args:
            analysis_results: Dictionary containing analysis module results
                            Expected keys: 'behaviour_analysis' with androguard_objects
            existing_strings: List of strings already collected by StringCollectionStrategy

        Returns:
            Enhanced list of string dictionaries with additional deep analysis findings.
            If deep analysis is unavailable, returns existing_strings unchanged.

        Raises:
            None: Method handles all exceptions gracefully and logs errors

        Single Responsibility: Handle deep string extraction from androguard objects.
        """
        all_strings = existing_strings.copy()
        deep_strings_extracted = 0
        # Track analysis counts for potential future use
        _ = 0  # xml_files_analyzed
        _ = 0  # smali_files_analyzed

        try:
            # Check if we have behaviour analysis results with stored androguard objects
            behaviour_results = analysis_results.get("behaviour_analysis", {})
            if hasattr(behaviour_results, "androguard_objects"):
                androguard_objs = behaviour_results.androguard_objects
                analysis_mode = androguard_objs.get("mode", "unknown")

                if analysis_mode == "deep":
                    self.logger.info("🔍 Using DEEP analysis objects for enhanced secret detection")

                    # Get APK object for file extraction
                    apk_obj = androguard_objs.get("apk_obj")
                    if apk_obj:
                        # This would delegate to XML and Smali extraction methods
                        # (keeping existing _extract_from_xml_files and _extract_from_smali_files)
                        xml_results = self._extract_xml_strings(apk_obj, all_strings)
                        smali_results = self._extract_smali_strings(apk_obj, all_strings)

                        deep_strings_extracted += xml_results + smali_results

                    # Extract strings from DEX objects
                    dex_obj = androguard_objs.get("dex_obj")
                    if dex_obj:
                        dex_strings = self._extract_dex_strings(dex_obj, all_strings)
                        deep_strings_extracted += dex_strings

                    self.logger.info(f"🔍 Deep analysis extracted {deep_strings_extracted} additional strings")
                else:
                    self.logger.debug("📱 Using FAST analysis mode - limited string sources")

        except Exception as e:
            self.logger.error(f"Deep string extraction failed: {str(e)}")

        return all_strings

    def _extract_xml_strings(self, apk_obj, all_strings: list[dict[str, Any]]) -> int:
        """Extract strings from XML files - delegates to existing method."""
        # This would use the existing _extract_from_xml_files method
        return 0  # Placeholder

    def _extract_smali_strings(self, apk_obj, all_strings: list[dict[str, Any]]) -> int:
        """Extract strings from Smali files - delegates to existing method."""
        # This would use the existing _extract_from_smali_files method
        return 0  # Placeholder

    def _extract_dex_strings(self, dex_obj, all_strings: list[dict[str, Any]]) -> int:
        """
        Extract strings from DEX objects using Androguard.

        This method processes DEX objects to extract string literals that may
        contain hardcoded secrets or sensitive information.

        Args:
            dex_obj: List of DEX objects from Androguard analysis
            all_strings: List to append extracted strings to (modified in-place)

        Returns:
            int: Number of strings successfully extracted

        Raises:
            None: Handles DEX parsing exceptions gracefully and logs errors
        """
        extracted_count = 0
        for i, dex in enumerate(dex_obj):
            try:
                dex_strings = dex.get_strings()
                for string in dex_strings:
                    string_val = str(string)
                    if string_val and len(string_val.strip()) > 0:
                        all_strings.append(
                            {
                                "value": string_val,
                                "location": f"DEX file {i+1}",
                                "file_path": f'classes{i+1 if i > 0 else ""}.dex',
                                "line_number": None,
                            }
                        )
                        extracted_count += 1
            except Exception as e:
                self.logger.error(f"Failed to extract strings from DEX {i}: {str(e)}")

        return extracted_count


class PatternDetectionStrategy:
    """
    Strategy for detecting secrets using compiled patterns.

    This strategy implements the core secret detection logic by applying
    54 different detection patterns to collected strings. It identifies
    secrets across multiple severity levels and provides detailed match information.

    Responsibilities:
    - Apply pattern matching to collected strings
    - Filter out strings too short for meaningful analysis
    - Delegate to existing pattern detection methods
    - Return structured detection results with metadata

    Design Pattern: Strategy Pattern (third phase of secret detection workflow)
    SOLID Principles: Single Responsibility (only handles pattern detection)
    """

    # B2: Required literal substrings (lower-cased) for patterns whose regex can only
    # match when the literal is present. Detection runs case-insensitively, so a match
    # guarantees the (lower-cased) literal appears in the (lower-cased) input; skipping
    # the regex when no listed literal is present therefore never drops a real match.
    # For patterns whose match is an alternation of prefixes, every listed literal is a
    # candidate and the prefilter passes if ANY of them is present. Patterns without an
    # obvious required literal (pure hex/base64/high-entropy, discord token, jenkins,
    # captcha) are intentionally omitted so they always run.
    _PATTERN_LITERALS: dict[str, list[str]] = {
        "pem_private_key": ["-----begin"],
        "ssh_private_key": ["-----begin openssh private key-----"],
        "aws_access_key": ["a3t", "akia", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "asia"],
        "aws_secret_key": ["aws"],
        "github_token": ["ghp_"],
        "github_fine_grained_token": ["github_pat_"],
        "github_token_in_url": ["github.com"],
        "google_oauth_token": ["ya29."],
        "google_service_account": ["service_account"],
        "google_api_key_aiza": ["aiza"],
        "google_maps_api_key": ["aiza"],
        "firebase_cloud_messaging_key": ["aaaa"],
        "firebase_realtime_db_key": ["firebase"],
        "aws_amplify_key": ["amplify"],
        "password_in_url": ["://"],
        "generic_password": ["pass", "pwd"],
        "generic_api_key": ["key"],
        "generic_secret": ["secret"],
        "jwt_token": ["ey"],
        "azure_client_secret": ["client_secret"],
        "heroku_api_key": ["heroku"],
        "stripe_api_key": ["_live_"],
        "gitlab_personal_token": ["glpat-"],
        "amazon_mws_auth_token": ["amzn.mws."],
        "facebook_access_token": ["eaacedeose0cba"],
        "facebook_oauth_secret": ["facebook"],
        "mailchimp_api_key": ["-us"],
        "mailgun_api_key": ["key-"],
        "picatic_api_key": ["sk_live_"],
        "square_access_token": ["sq0atp-", "eaaa"],
        "square_oauth_secret": ["sq0csp-"],
        "twitter_access_token": ["twitter"],
        "twitter_oauth_secret": ["twitter"],
        "authorization_basic": ["basic"],
        "authorization_bearer": ["bearer"],
        "slack_token": ["xox"],
        "slack_token_legacy": ["xox"],
        "mongodb_uri": ["mongodb"],
        "postgresql_uri": ["postgres"],
        "mysql_uri": ["mysql://"],
        "redis_uri": ["redis://"],
        "cloudinary_url": ["cloudinary://"],
        "firebase_url": ["firebaseio.com"],
        "slack_webhook_url": ["hooks.slack.com"],
        "ssh_public_key": ["ssh-"],
        "pem_certificate": ["-----begin certificate-----"],
        "smali_const_string_api_key": ["const-string"],
        "android_build_config_key": ["buildconfig"],
        "android_resources_api_key": ["r.string."],
        "stripe_restricted_key": ["rk_live_"],
        "paypal_braintree_token": ["access_token$production$"],
        "s3_bucket_url": ["s3.amazonaws.com"],
        # PR-5 structural client-credential patterns.
        "branch_io_key": ["key_live_"],
        "admob_app_id": ["ca-app-pub-"],
        "crashlytics_api_key": ["crashlytics", "fabric"],
    }

    def __init__(self, detection_patterns: dict[str, Any], logger, validator=None):
        """Initialize with detection patterns and logger.

        B2: Environment-dependent limits and the (~60) regex patterns are resolved once
        here instead of being recomputed for every scanned string. Patterns are
        pre-compiled with re.IGNORECASE and paired with cheap literal prefilters.

        Args:
            detection_patterns: The secret-detection pattern registry.
            logger: Logger instance.
            validator: Optional :class:`SecretValidator`. When None (the default) the
                strategy behaves exactly as before (regex match -> append, no gating).
                When provided, each match is validated/reclassified for precision and
                recall before being reported.
        """
        self.detection_patterns = detection_patterns
        self.logger = logger
        self.validator = validator

        # Determine environment-based limits once (env vars do not change at runtime).
        # These mirror the values previously computed per call in _safe_regex_search.
        import os

        self._is_ci = any(env_var in os.environ for env_var in ["CI", "GITHUB_ACTIONS", "TRAVIS", "JENKINS_URL"])
        self._text_limit = 2000 if self._is_ci else 10000  # 2KB in CI, 10KB normally
        self._pattern_length_limit = 150 if self._is_ci else 300  # stricter in CI

        # Compile each detection pattern exactly once (was implicitly recompiled per
        # string via _safe_regex_search / re.search on every call).
        self._compiled_patterns = self._precompile_patterns(detection_patterns)

    def _precompile_patterns(self, detection_patterns: dict[str, Any]) -> list[dict[str, Any]]:
        """Compile detection patterns once, preserving the original pattern order.

        Applies the same pattern-level safety filtering that _safe_regex_search used to
        perform per call (pattern length, dangerous constructs, quantifier combos) and
        attaches the literal prefilter. Each returned entry contains:
        - 'name': pattern name
        - 'config': the original pattern configuration dict
        - 'regex': compiled re.Pattern (IGNORECASE) or None when the pattern is skipped
        - 'literals': list of lower-cased candidate literals (ANY must match), or []
        """
        compiled: list[dict[str, Any]] = []
        for pattern_name, pattern_config in detection_patterns.items():
            pattern_str = pattern_config.get("pattern", "")
            regex = None
            if self._is_pattern_safe(pattern_str, pattern_name):
                try:
                    # Per-pattern case sensitivity. Most patterns stay case-insensitive,
                    # but prefix-defined credentials (e.g. AWS key ids) set
                    # case_sensitive=True so IGNORECASE cannot match lowercase look-alikes.
                    flags = 0 if pattern_config.get("case_sensitive") else re.IGNORECASE
                    regex = re.compile(pattern_str, flags)
                except re.error as e:
                    self.logger.debug(f"Skipping uncompilable pattern {pattern_name}: {e}")
                    regex = None
            compiled.append(
                {
                    "name": pattern_name,
                    "config": pattern_config,
                    "regex": regex,
                    "literals": self._PATTERN_LITERALS.get(pattern_name, []),
                }
            )
        return compiled

    def _is_pattern_safe(self, pattern: str, pattern_name: str) -> bool:
        """Run the pattern-level safety checks from _safe_regex_search once, at compile
        time, instead of on every scanned string. Returns False when the pattern would
        previously have been skipped (yielding no match) by _safe_regex_search.
        """
        if len(pattern) > self._pattern_length_limit:
            self.logger.debug(f"Skipping complex pattern ({len(pattern)} chars) for {pattern_name}")
            return False

        # Only reject truly dangerous constructs that cause exponential backtracking.
        dangerous_patterns = [r"(.*)*", r"(.+)+", r"(.*)+", r"(.+)*", r".*{.*}.*", r".+{.+}.+"]
        for dangerous in dangerous_patterns:
            if dangerous in pattern:
                self.logger.debug(f"Skipping pattern with dangerous constructs {pattern_name}: {dangerous}")
                return False

        # Reject excessive quantifier combinations (not individual quantifiers).
        quantifier_combos = pattern.count(".*") + pattern.count(".+") + pattern.count("*+") + pattern.count("+*")
        if quantifier_combos > 2:
            self.logger.debug(f"Skipping pattern with {quantifier_combos} quantifier combinations: {pattern_name}")
            return False

        return True

    def _safe_regex_search(self, pattern: str, text: str, pattern_name: str = "unknown") -> re.Match[str] | None:
        """Perform a regex search with protection against catastrophic backtracking.

        Args:
            pattern: The regex pattern to search for
            text: The text to search in
            pattern_name: Name of the pattern for logging

        Returns:
            Match object if found, None otherwise
        """
        try:
            import os

            # Detect CI environment for stricter limits
            is_ci = any(env_var in os.environ for env_var in ["CI", "GITHUB_ACTIONS", "TRAVIS", "JENKINS_URL"])

            # Balanced safety checks - stricter in CI, more permissive in normal use
            text_limit = 2000 if is_ci else 10000  # 2KB in CI, 10KB normally
            pattern_limit = 150 if is_ci else 300  # Stricter pattern limit in CI

            if len(text) > text_limit:
                self.logger.debug(f"Skipping long text ({len(text)} chars) for pattern {pattern_name}")
                return None

            if len(pattern) > pattern_limit:
                self.logger.debug(f"Skipping complex pattern ({len(pattern)} chars) for {pattern_name}")
                return None

            # Only check for truly dangerous patterns that cause exponential backtracking
            dangerous_patterns = [
                r"(.*)*",  # Nested quantifiers
                r"(.+)+",
                r"(.*)+",
                r"(.+)*",
                r".*{.*}.*",  # Multiple wildcards with ranges
                r".+{.+}.+",
            ]

            # Check for truly dangerous constructs only
            for dangerous in dangerous_patterns:
                if dangerous in pattern:
                    self.logger.debug(f"Skipping pattern with dangerous constructs {pattern_name}: {dangerous}")
                    return None

            # Check for excessive quantifier combinations (not individual quantifiers)
            quantifier_combos = pattern.count(".*") + pattern.count(".+") + pattern.count("*+") + pattern.count("+*")
            if quantifier_combos > 2:
                self.logger.debug(f"Skipping pattern with {quantifier_combos} quantifier combinations: {pattern_name}")
                return None

            # Simple, fast regex search with IGNORECASE
            match = re.search(pattern, text, re.IGNORECASE)
            return match

        except Exception as e:
            self.logger.debug(f"Regex error for pattern {pattern_name}: {str(e)}")
            return None

    def detect_secrets(self, strings_with_location: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect secrets in strings using pattern matching.

        Balanced approach: thorough in normal use, conservative in CI/integration environments.

        This method applies the comprehensive set of 54+ secret detection patterns
        to identify hardcoded secrets across four severity levels (CRITICAL, HIGH,
        MEDIUM, LOW). It filters out very short strings and applies pattern matching
        logic to find potential secrets.

        Args:
            strings_with_location: List of string dictionaries from collection strategies
                                 Each dict contains 'value', 'location', 'file_path', 'line_number'

        Returns:
            List of detection dictionaries, each containing:
            - 'type': Type of secret detected (e.g., 'AWS Access Key')
            - 'severity': Severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
            - 'pattern_name': Name of the pattern that matched
            - 'value': The detected secret value
            - 'location': Source location information
            - 'file_path': File path if available
            - 'line_number': Line number if available

        Raises:
            None: Method handles pattern matching exceptions gracefully

        Single Responsibility: Apply pattern detection to collected strings.
        """
        import os

        # Check if we're running in CI environment and limit processing
        is_ci = any(env_var in os.environ for env_var in ["CI", "GITHUB_ACTIONS", "TRAVIS", "JENKINS_URL"])

        detected_secrets = []

        # In CI environments, limit strings; in normal use, process all
        max_strings = 500 if is_ci else len(strings_with_location)  # Increased from 100 to 500
        strings_to_process = strings_with_location[:max_strings]

        self.logger.info(f"🔍 Scanning {len(strings_to_process)} strings for secrets...")
        if is_ci and len(strings_with_location) > max_strings:
            self.logger.debug(f"CI mode: Limited to {max_strings}/{len(strings_with_location)} strings for performance")

        for string_data in strings_to_process:
            string_value = string_data.get("value", "")
            if not string_value or len(string_value.strip()) < 3:
                continue

            # Apply pattern detection (this would use existing detection patterns)
            matches = self._apply_patterns_to_string(string_value, string_data)
            detected_secrets.extend(matches)

        self.logger.info(f"🔍 Found {len(detected_secrets)} potential secrets")
        return detected_secrets

    def _apply_patterns_to_string(self, string_value: str, string_data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Apply detection patterns to a single string.

        This method serves as a delegation point to the existing pattern matching
        implementation. It would iterate through all detection patterns and apply
        them to the given string value.

        Args:
            string_value: The string to analyze for secrets
            string_data: Dictionary containing location and metadata

        Returns:
            List of pattern matches for this specific string

        Note:
            This is currently a placeholder that delegates to existing methods.
            The actual implementation would contain the core pattern matching logic.
        """
        # Apply detection patterns to the string
        matches = []

        # Skip very long strings to prevent catastrophic backtracking
        if len(string_value) > 50000:  # 50KB limit
            self.logger.debug(f"Skipping very long string ({len(string_value)} chars) to prevent timeout")
            return matches

        # B2: Per-string text-length guard. This check previously lived inside
        # _safe_regex_search and ran once per pattern; applying it once per string is
        # equivalent (an over-long text yields no match for any pattern) and much cheaper.
        if len(string_value) > self._text_limit:
            self.logger.debug(f"Skipping long text ({len(string_value)} chars) for secret scanning")
            return matches

        # B2: Lower-cased view reused by every literal prefilter below. Detection is
        # case-insensitive, so a case-insensitive literal test is a sound prefilter.
        lowered_value = string_value.lower()

        # B2: Iterate the pre-compiled patterns (compiled once in __init__) instead of
        # recompiling each pattern for every string.
        for entry in self._compiled_patterns:
            regex = entry["regex"]
            if regex is None:
                # Pattern was filtered out by the safety checks - preserves the previous
                # behaviour where _safe_regex_search returned None (no match) for it.
                continue

            # Cheap literal prefilter: skip the expensive regex when a required literal
            # cannot be present. Only skips when the regex could not have matched anyway.
            literals = entry["literals"]
            if literals and not any(literal in lowered_value for literal in literals):
                continue

            try:
                match = regex.search(string_value)
                if match:
                    pattern_config = entry["config"]
                    severity = pattern_config.get("severity", "MEDIUM")
                    confidence = None
                    classification_label = None
                    classification_basis = None

                    # PR-5: gate/reclassify the match when a validator is wired in.
                    # Extract the capture group (the actual secret) when present so
                    # entropy/allowlist checks run on the secret, not the wrapper text.
                    if self.validator is not None:
                        matched_value = match.group(1) if match.groups() else match.group(0)
                        verdict = self.validator.evaluate(
                            matched_value, string_value, entry["name"], pattern_config
                        )
                        if verdict.rejected:
                            continue
                        if verdict.severity:
                            severity = verdict.severity
                        confidence = verdict.confidence
                        classification_label = verdict.classification_label
                        classification_basis = verdict.classification_basis

                    detection = {
                        "type": pattern_config.get("description", entry["name"]),
                        "severity": severity,
                        "pattern_name": entry["name"],
                        "value": match.group(),
                        "full_context": string_value,
                        "location": string_data.get("location", ""),
                        "file_path": string_data.get("file_path"),
                        "line_number": string_data.get("line_number"),
                    }
                    if confidence is not None:
                        detection["confidence"] = confidence
                        detection["classification_label"] = classification_label
                        detection["classification_basis"] = classification_basis
                    matches.append(detection)

            except Exception as e:
                self.logger.warning(f"Error applying pattern {entry['name']}: {str(e)}")
                continue

        return matches


class ResultClassificationStrategy:
    """
    Strategy for classifying detection results by severity.

    This strategy organizes detected secrets into severity-based categories
    and prepares them for final SecurityFinding generation. It creates both
    terminal display formats and structured evidence entries.

    Responsibilities:
    - Classify detected secrets by severity level
    - Create terminal display formats with location information
    - Generate structured evidence entries for JSON export
    - Prepare classified results for finding generation

    Design Pattern: Strategy Pattern (fourth phase of secret detection workflow)
    SOLID Principles: Single Responsibility (only handles result classification)
    """

    # B1b: Maximum number of sample evidence entries retained per severity. The finding
    # generator only slices the first 10-20 entries, so 50 is a safe upper bound while
    # the running counters preserve the true totals for the finding titles.
    _SAMPLE_LIMIT = 50

    def classify_by_severity(self, detected_secrets: list[dict[str, Any]]) -> dict[str, Any]:
        """Classify detected secrets by severity level.

        This method processes detected secrets and organizes them into severity
        categories. It creates two types of output: terminal display format for
        logging and structured evidence entries for JSON export.

        Args:
            detected_secrets: List of detection dictionaries from PatternDetectionStrategy
                            Each dict contains type, severity, pattern_name, value, location info

        Returns:
            Dictionary containing:
            - 'findings': Dict with severity keys ('critical', 'high', 'medium', 'low')
                         Values are lists of formatted strings for terminal display
            - 'secrets': Dict with severity keys containing structured evidence entries
                        Each entry has type, severity, value, location, preview, etc.

        Raises:
            None: Method handles classification exceptions gracefully

        Single Responsibility: Organize findings into severity categories.
        """
        classified_findings = {"critical": [], "high": [], "medium": [], "low": []}
        detected_secrets_by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        # B1b: running TRUE totals per severity (after de-duplication). The sample
        # buffers above are capped at _SAMPLE_LIMIT, so a 100k+ element LOW list is no
        # longer materialised; these counters preserve the exact totals used for the
        # finding titles/descriptions (e.g. "LOW: 13785 Potential Information Leakage").
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Deduplicate secrets - track by (type, value) pairs to avoid duplicates
        seen_secrets = set()

        for detection in detected_secrets:
            # Create deduplication key based on secret type and normalized value
            dedup_key = (detection["type"], detection["value"][:50])  # Use first 50 chars for dedup

            if dedup_key in seen_secrets:
                continue  # Skip duplicate
            seen_secrets.add(dedup_key)

            # Classify by severity
            severity = detection["severity"].lower()
            if severity not in classified_findings:
                continue

            # Count every unique detection (true total, used for the finding titles).
            counts[severity] += 1

            # B1b: only materialise a bounded sample of evidence entries / terminal
            # display strings. The finding generator only ever slices the first 10-20
            # items, so buffering _SAMPLE_LIMIT entries is behaviourally identical while
            # avoiding the unbounded per-detection dict + f-string construction.
            if len(classified_findings[severity]) >= self._SAMPLE_LIMIT:
                continue

            # Create detailed evidence entry
            evidence_entry = {
                "type": detection["type"],
                "severity": detection["severity"],
                "pattern_name": detection["pattern_name"],
                "value": detection["value"],
                "full_context": detection.get("full_context", detection["value"]),
                "location": detection.get("location", "Unknown"),
                "file_path": detection.get("file_path"),
                "line_number": detection.get("line_number"),
                "preview": detection["value"][:100] + ("..." if len(detection["value"]) > 100 else ""),
            }

            # PR-5: thread the validator's confidence / classification into the
            # evidence entry when present (absent when no validator was wired in).
            if "confidence" in detection:
                evidence_entry["confidence"] = detection["confidence"]
                evidence_entry["classification_label"] = detection.get("classification_label")
                evidence_entry["classification_basis"] = detection.get("classification_basis")

            # Format for terminal display with location info
            location_info = detection.get("location", "Unknown")
            if detection.get("file_path"):
                location_info = detection["file_path"]
                if detection.get("line_number"):
                    location_info += f":{detection['line_number']}"

            terminal_display = f"🔑 [{detection['severity']}] {detection['type']}: {evidence_entry['preview']} (found in {location_info})"

            classified_findings[severity].append(terminal_display)
            detected_secrets_by_severity[severity].append(evidence_entry)

        return {"findings": classified_findings, "secrets": detected_secrets_by_severity, "counts": counts}


class FindingGenerationStrategy:
    """
    Strategy for generating SecurityFinding objects from classified results.

    This strategy creates the final SecurityFinding objects that integrate with
    the broader security assessment framework. It generates findings with
    secret-finder style messaging and comprehensive remediation guidance.

    Responsibilities:
    - Generate SecurityFinding objects for each severity level
    - Create secret-finder style titles and descriptions with emojis
    - Provide comprehensive remediation steps and recommendations
    - Limit evidence lists to prevent overwhelming output

    Design Pattern: Strategy Pattern (final phase of secret detection workflow)
    SOLID Principles: Single Responsibility (only handles finding generation)
    """

    def __init__(self, owasp_category: str):
        """Initialize with OWASP category."""
        self.owasp_category = owasp_category

    def generate_security_findings(self, classified_results: dict[str, Any]) -> list[SecurityFinding]:
        """Generate SecurityFinding objects from classified detection results.

        This method creates SecurityFinding objects for each severity level that
        contains detected secrets. It uses secret-finder style messaging with
        emojis and provides comprehensive remediation guidance.

        Args:
            classified_results: Dictionary from ResultClassificationStrategy containing:
                              - 'findings': Severity-categorized terminal display strings
                              - 'secrets': Severity-categorized structured evidence entries

        Returns:
            List of SecurityFinding objects, one for each severity level that
            contains detected secrets. Empty severity levels are omitted.

        SecurityFinding Structure:
        - category: OWASP A02:2021-Cryptographic Failures
        - severity: AnalysisSeverity enum value (CRITICAL, HIGH, MEDIUM, LOW)
        - title: Secret-finder style title with emoji and count
        - description: Detailed explanation of security implications
        - evidence: Limited list of findings (10-20 items max)
        - recommendation: Actionable security recommendation with emoji
        - remediation_steps: Detailed step-by-step remediation guidance

        Raises:
            None: Method handles finding generation exceptions gracefully

        Single Responsibility: Create final SecurityFinding objects with proper formatting.
        """
        findings: list[SecurityFinding] = []
        classified_findings = classified_results["findings"]
        # B1b: prefer the TRUE per-severity totals when provided. The 'findings' sample
        # buffers are capped by ResultClassificationStrategy, so their length is no
        # longer the real count. Fall back to the sample length for callers/tests that
        # pass classifications without a 'counts' entry (behaviour-preserving).
        counts = classified_results.get("counts")

        def _count(severity: str) -> int:
            if counts is not None:
                return counts.get(severity, len(classified_findings[severity]))
            return len(classified_findings[severity])

        # Create findings based on severity levels with secret-finder style messaging
        if classified_findings["critical"]:
            findings.append(self._build_critical_severity_finding(classified_findings, _count("critical")))

        if classified_findings["high"]:
            findings.append(self._build_high_severity_finding(classified_findings, _count("high")))

        if classified_findings["medium"]:
            findings.append(self._build_medium_severity_finding(classified_findings, _count("medium")))

        if classified_findings["low"]:
            findings.append(self._build_low_severity_finding(classified_findings, _count("low")))

        return findings

    def _build_critical_severity_finding(self, classified_findings: dict[str, Any], count: int) -> SecurityFinding:
        """Build the CRITICAL severity SecurityFinding from classified findings."""
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.CRITICAL,
            title=f"🔴 CRITICAL: {count} Hard-coded Secrets Found",
            description=f"Found {count} critical severity secrets that pose immediate security risks. These include private keys, AWS credentials, and other highly sensitive data that could lead to complete system compromise.",
            evidence=classified_findings["critical"][:10],
            recommendations=[
                "🚨 IMMEDIATE ACTION REQUIRED: Remove all hard-coded secrets and use secure secret management solutions like environment variables, HashiCorp Vault, or cloud-native secret stores. Rotate any exposed credentials immediately.",
                "1. Remove hard-coded secrets from source code immediately",
                "2. Rotate any exposed credentials (API keys, passwords, tokens)",
                "3. Implement environment variables or secure secret management",
                "4. Add secrets scanning to CI/CD pipeline to prevent future issues",
                "5. Audit access logs for any unauthorized usage of exposed credentials",
            ],
        )

    def _build_high_severity_finding(self, classified_findings: dict[str, Any], count: int) -> SecurityFinding:
        """Build the HIGH severity SecurityFinding from classified findings."""
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.HIGH,
            title=f"🟠 HIGH: {count} Potential Secrets Found",
            description=f"Found {count} high severity potential secrets including API keys, tokens, and service credentials that could provide unauthorized access to systems and data.",
            evidence=classified_findings["high"][:10],
            recommendations=[
                "⚠️ HIGH PRIORITY: Review and remove suspected secrets. Implement proper secret management practices.",
                "1. Review each detected string to confirm if it's a legitimate secret",
                "2. Remove confirmed secrets and replace with secure alternatives",
                "3. Consider using build-time secret injection for legitimate secrets",
                "4. Implement automated secret scanning in development workflow",
            ],
        )

    def _build_medium_severity_finding(self, classified_findings: dict[str, Any], count: int) -> SecurityFinding:
        """Build the MEDIUM severity SecurityFinding from classified findings."""
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.MEDIUM,
            title=f"🟡 MEDIUM: {count} Suspicious Strings Found",
            description=f"Found {count} medium severity suspicious strings that may contain sensitive information like database URLs, SSH keys, or encoded secrets.",
            evidence=classified_findings["medium"][:15],
            recommendations=[
                "⚠️ Review suspicious strings for potential sensitive data exposure. Consider if these should be externalized.",
                "1. Review each suspicious string for sensitive content",
                "2. Consider externalizing configuration data to secure stores",
                "3. Validate that exposed information doesn't aid attackers",
                "4. Apply principle of least privilege to any exposed connection strings",
            ],
        )

    def _build_low_severity_finding(self, classified_findings: dict[str, Any], count: int) -> SecurityFinding:
        """Build the LOW severity SecurityFinding from classified findings."""
        return SecurityFinding(
            category=self.owasp_category,
            severity=AnalysisSeverity.LOW,
            title=f"🔵 LOW: {count} Potential Information Leakage",
            description=f"Found {count} low severity strings that may leak information about system configuration, third-party services, or internal infrastructure.",
            evidence=classified_findings["low"][:20],
            recommendations=[
                "ℹ️ Review for information disclosure. Consider if exposed details provide unnecessary information to potential attackers.",
                "1. Review exposed service URLs and tokens for necessity",
                "2. Consider using generic identifiers where possible",
                "3. Validate that exposed information follows security by design principles",
            ],
        )

    def _detect_hardcoded_keys_with_location(self, strings_with_location: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect hardcoded keys using comprehensive pattern matching with location information."""
        detections = []

        for string_info in strings_with_location:
            string_value = string_info["value"]
            if not isinstance(string_value, str):
                continue

            # Apply length filters
            if (
                len(string_value) < self.length_filters["min_key_length"]
                or len(string_value) > self.length_filters["max_key_length"]
            ):
                continue

            # Check each detection pattern
            for key_type, pattern_config in self.key_detection_patterns.items():
                # Check if this pattern type is enabled
                if not self._is_pattern_enabled(key_type):
                    continue

                pattern = pattern_config["pattern"]

                try:
                    match = re.search(pattern, string_value, re.IGNORECASE | re.MULTILINE)
                    if match:
                        # Extract the actual match (might be a capture group)
                        matched_value = match.group(1) if match.groups() else match.group(0)

                        # Additional validation checks
                        if self._validate_key_detection(matched_value, pattern_config, key_type):
                            detection = {
                                "type": pattern_config["description"],
                                "value": matched_value,  # Use the extracted match, not the full string
                                "full_context": string_value,  # Keep the full context for reference
                                "severity": pattern_config["severity"],
                                "pattern_name": key_type,
                                "location": string_info["location"],
                                "file_path": string_info["file_path"],
                                "line_number": string_info["line_number"],
                            }
                            detections.append(detection)
                            break  # Don't match multiple patterns for the same string

                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern for {key_type}: {e}")
                    continue

        return detections

    def _is_pattern_enabled(self, key_type: str) -> bool:
        """Check if a pattern type is enabled in configuration."""
        # Map pattern names to configuration keys - updated with all new patterns
        pattern_mapping = {
            # Critical patterns
            "pem_private_key": "pem_keys",  # pragma: allowlist secret
            "ssh_private_key": "ssh_keys",  # pragma: allowlist secret
            "aws_access_key": "api_keys",  # pragma: allowlist secret
            "aws_secret_key": "api_keys",  # pragma: allowlist secret
            "github_token": "api_keys",
            "github_fine_grained_token": "api_keys",
            "github_token_in_url": "api_keys",
            "google_oauth_token": "api_keys",
            "google_service_account": "api_keys",
            "google_api_key_aiza": "api_keys",  # pragma: allowlist secret
            "firebase_cloud_messaging_key": "api_keys",
            "password_in_url": "api_keys",  # pragma: allowlist secret
            # High severity patterns
            "generic_password": "api_keys",
            "generic_api_key": "api_keys",
            "generic_secret": "api_keys",
            "jwt_token": "jwt_tokens",
            "azure_client_secret": "api_keys",
            "heroku_api_key": "api_keys",
            "stripe_api_key": "api_keys",
            "discord_bot_token": "api_keys",
            "gitlab_personal_token": "api_keys",
            "amazon_mws_auth_token": "api_keys",
            "facebook_access_token": "api_keys",
            "facebook_oauth_secret": "api_keys",
            "mailchimp_api_key": "api_keys",
            "mailgun_api_key": "api_keys",
            "picatic_api_key": "api_keys",
            "square_access_token": "api_keys",
            "square_oauth_secret": "api_keys",
            "twitter_access_token": "api_keys",
            "twitter_oauth_secret": "api_keys",
            "authorization_basic": "api_keys",
            "authorization_bearer": "api_keys",
            "slack_token": "api_keys",
            # Medium severity patterns
            "google_cloud_api_key": "api_keys",
            "slack_token_legacy": "api_keys",
            "mongodb_uri": "database_connections",
            "postgresql_uri": "database_connections",
            "mysql_uri": "database_connections",
            "redis_uri": "database_connections",
            "cloudinary_url": "database_connections",
            "firebase_url": "database_connections",
            "slack_webhook_url": "api_keys",
            "ssh_public_key": "ssh_keys",
            "pem_certificate": "pem_keys",
            "hex_key_256": "hex_keys",
            "hex_key_128": "hex_keys",
            # Low severity patterns
            "jenkins_api_token": "api_keys",
            "stripe_restricted_key": "api_keys",
            "paypal_braintree_token": "api_keys",
            "google_captcha_key": "api_keys",
            "s3_bucket_url": "api_keys",
            "base64_key_long": "base64_keys",
            "base64_key_medium": "base64_keys",
            "high_entropy_string": "high_entropy_strings",
            "smali_const_string_api_key": "api_keys",
        }

        config_key = pattern_mapping.get(key_type, "api_keys")  # Default to api_keys
        return self.enabled_patterns.get(config_key, True)

    def _validate_key_detection(self, string: str, pattern_config: dict[str, Any], key_type: str) -> bool:
        """Validate key detection with additional checks."""
        # Check minimum entropy using configured thresholds
        min_entropy = pattern_config.get("min_entropy")
        if min_entropy is None:
            # Use configured entropy thresholds based on key type
            if "base64" in key_type:
                min_entropy = self.entropy_thresholds["min_base64_entropy"]
            elif "hex" in key_type:
                min_entropy = self.entropy_thresholds["min_hex_entropy"]
            elif key_type == "high_entropy_string":
                min_entropy = self.entropy_thresholds["min_generic_entropy"]

        if min_entropy and self._calculate_entropy(string) < min_entropy:
            return False

        # Check maximum length if specified
        max_length = pattern_config.get("max_length")
        if max_length and len(string) > max_length:
            return False

        # Check if context is required (if context detection is enabled)
        context_required = pattern_config.get("context_required", [])
        if context_required and self.context_detection_enabled and not self._has_required_context(string, context_required):
            # In strict mode, require context for all matches with context_required
            if self.context_strict_mode:
                return False
            # In non-strict mode, just log a warning but allow the detection
            self.logger.debug(f"Key detected without required context: {key_type}")

        # Skip common false positives
        return not self._is_false_positive(string)

    def _extract_from_xml_files(self, apk_obj, all_strings_with_location: list[dict[str, Any]]) -> dict[str, int]:
        """
        Extract strings from XML files within the APK, particularly targeting strings.xml files.

        Args:
            apk_obj: Androguard APK object
            all_strings_with_location: List to append extracted strings with location info

        Returns:
            Dict with files_analyzed and strings_extracted counts
        """
        files_analyzed = 0
        strings_extracted = 0

        try:
            # Get all XML files from the APK
            xml_files = [f for f in apk_obj.get_files() if f.endswith(".xml")]

            self.logger.debug(f"Found {len(xml_files)} XML files in APK")

            for xml_file in xml_files:
                try:
                    # Focus on common resource files that may contain API keys
                    if any(
                        target in xml_file.lower()
                        for target in ["strings.xml", "config.xml", "keys.xml", "api.xml", "secrets.xml"]
                    ):
                        files_analyzed += 1

                        # Get XML content
                        xml_data = apk_obj.get_file(xml_file)
                        if xml_data:
                            strings_extracted = self._extract_strings_from_single_xml(
                                xml_data, xml_file, strings_extracted, all_strings_with_location
                            )

                except Exception as e:
                    self.logger.debug(f"Error processing XML file {xml_file}: {e}")

        except Exception as e:
            self.logger.debug(f"Error in XML file extraction: {e}")

        self.logger.debug(
            f"XML analysis complete: {files_analyzed} files analyzed, {strings_extracted} strings extracted"
        )
        return {"files_analyzed": files_analyzed, "strings_extracted": strings_extracted}

    def _extract_strings_from_single_xml(
        self, xml_data, xml_file: str, strings_extracted: int, all_strings_with_location: list[dict[str, Any]]
    ) -> int:
        """Extract strings from a single XML file, falling back to text parsing on error."""
        # Try to decode as XML
        try:
            from xml.etree import ElementTree as ET

            # Parse XML content (secure: parsing trusted APK-extracted content)
            parser = ET.XMLParser()
            parser.entity = {}  # Disable entity processing for security
            root = ET.fromstring(xml_data, parser=parser)

            strings_extracted = self._extract_strings_from_xml_elements(
                root, xml_file, strings_extracted, all_strings_with_location
            )

            self.logger.debug(f"Extracted {strings_extracted} strings from {xml_file}")

        except ET.ParseError:
            # Try as plain text if XML parsing fails
            strings_extracted = self._extract_strings_from_xml_text(
                xml_data, xml_file, strings_extracted, all_strings_with_location
            )
        return strings_extracted

    def _extract_strings_from_xml_elements(
        self, root, xml_file: str, strings_extracted: int, all_strings_with_location: list[dict[str, Any]]
    ) -> int:
        """Extract strings from XML element text, attributes, and string resources."""
        # Extract strings from XML elements and attributes
        for elem in root.iter():
            # Check element text content
            if elem.text and elem.text.strip():
                text_content = elem.text.strip()
                if len(text_content) > 8:  # Skip very short strings
                    all_strings_with_location.append(
                        {
                            "value": text_content,
                            "location": "XML element text",
                            "file_path": xml_file,
                            "line_number": None,
                        }
                    )
                    strings_extracted += 1

            # Check attributes for potential API keys
            for attr_name, attr_value in elem.attrib.items():
                if attr_value and len(attr_value) > 8:
                    # Special handling for common API key attribute names
                    if any(
                        key_hint in attr_name.lower()
                        for key_hint in ["key", "token", "secret", "api", "auth"]
                    ):
                        all_strings_with_location.append(
                            {
                                "value": attr_value,
                                "location": f"XML attribute ({attr_name})",
                                "file_path": xml_file,
                                "line_number": None,
                            }
                        )
                        strings_extracted += 1
                    # Also extract attribute names that might be keys themselves
                    elif len(attr_name) > 16:
                        all_strings_with_location.append(
                            {
                                "value": attr_name,
                                "location": "XML attribute name",
                                "file_path": xml_file,
                                "line_number": None,
                            }
                        )
                        strings_extracted += 1

                # Look for specific patterns like <string name="google_api_key">AIzaSy...</string>
                if elem.tag == "string" and "name" in elem.attrib:
                    string_name = elem.attrib["name"]
                    if any(
                        key_hint in string_name.lower()
                        for key_hint in ["key", "token", "secret", "api", "auth", "password"]
                    ) and elem.text and elem.text.strip() and len(elem.text.strip()) > 8:
                        all_strings_with_location.append(
                            {
                                "value": elem.text.strip(),
                                "location": f"XML string resource ({string_name})",
                                "file_path": xml_file,
                                "line_number": None,
                            }
                        )
                        strings_extracted += 1
        return strings_extracted

    def _extract_strings_from_xml_text(
        self, xml_data, xml_file: str, strings_extracted: int, all_strings_with_location: list[dict[str, Any]]
    ) -> int:
        """Extract key-value strings from XML content parsed as plain text."""
        try:
            text_content = xml_data.decode("utf-8", errors="ignore")
            # Look for key-value patterns in the text
            lines = text_content.split("\n")
            for line_no, line in enumerate(lines, 1):
                line = line.strip()
                if len(line) > 16 and any(
                    keyword in line.lower() for keyword in ["key", "token", "secret", "api"]
                ):
                    all_strings_with_location.append(
                        {
                            "value": line,
                            "location": "XML file content",
                            "file_path": xml_file,
                            "line_number": line_no,
                        }
                    )
                    strings_extracted += 1
        except UnicodeDecodeError:
            self.logger.debug(f"Could not decode {xml_file} as text")
        return strings_extracted

    def _extract_from_smali_files(self, apk_obj, all_strings_with_location: list[dict[str, Any]]) -> dict[str, int]:
        """
        Extract const-string patterns from Smali code analysis.

        This method attempts to access decompiled Smali code or simulate Smali analysis
        by examining DEX bytecode for const-string instructions.

        Args:
            apk_obj: Androguard APK object
            all_strings_with_location: List to append extracted strings with location info

        Returns:
            Dict with files_analyzed and strings_extracted counts
        """
        files_analyzed = 0
        strings_extracted = 0

        try:
            # Since we don't have direct access to Smali files in the APK object,
            # we'll analyze the DEX bytecode for const-string patterns

            from androguard.core.bytecodes import dvm

            # Get DEX objects from the APK
            for dex_name in apk_obj.get_dex_names():
                try:
                    dex = apk_obj.get_dex(dex_name)
                    if dex:
                        files_analyzed += 1

                        # Parse DEX file
                        dex_vm = dvm.DalvikVMFormat(dex)

                        strings_extracted += self._extract_const_strings_from_dex(dex_vm, all_strings_with_location)

                except Exception as e:
                    self.logger.debug(f"Error processing DEX {dex_name}: {e}")
                    continue

        except Exception as e:
            self.logger.debug(f"Error in Smali/DEX analysis: {e}")

        self.logger.debug(
            f"Smali analysis complete: {files_analyzed} DEX files analyzed, {strings_extracted} const-string patterns extracted"
        )
        return {"files_analyzed": files_analyzed, "strings_extracted": strings_extracted}

    def _extract_const_strings_from_dex(self, dex_vm, all_strings_with_location: list[dict[str, Any]]) -> int:
        """Extract const-string secrets from all app classes in a parsed DEX object."""
        strings_extracted = 0
        # Iterate through classes
        for class_def in dex_vm.get_classes():
            class_name = class_def.get_name()

            # Skip system classes to focus on app code
            if class_name.startswith(("Landroid/", "Ljava/")):
                continue

            strings_extracted += self._extract_const_strings_from_class(
                dex_vm, class_def, class_name, all_strings_with_location
            )
        return strings_extracted

    def _extract_const_strings_from_class(
        self, dex_vm, class_def, class_name: str, all_strings_with_location: list[dict[str, Any]]
    ) -> int:
        """Extract const-string secrets from all methods of a single class."""
        strings_extracted = 0
        try:
            # Get methods in the class
            for method in class_def.get_methods():
                method_name = method.get_name()

                # Get method bytecode
                if method.get_code():
                    bytecode = method.get_code()

                    strings_extracted += self._extract_const_strings_from_method(
                        dex_vm, bytecode, method_name, class_name, all_strings_with_location
                    )

        except Exception as e:
            self.logger.debug(f"Error analyzing method {method_name} in {class_name}: {e}")
        return strings_extracted

    def _extract_const_strings_from_method(
        self, dex_vm, bytecode, method_name: str, class_name: str, all_strings_with_location: list[dict[str, Any]]
    ) -> int:
        """Extract const-string secrets from the bytecode of a single method."""
        strings_extracted = 0
        # Look for const-string instructions in the bytecode
        for instruction in bytecode.get_bc().get():
            if instruction.get_name() == "const-string":
                # Extract the string value from const-string instruction
                try:
                    string_idx = instruction.get_ref_off_size()[0]
                    string_value = dex_vm.get_string(string_idx)

                    # Check if this looks like a potential secret
                    if string_value and len(string_value) > 8 and (
                        any(
                            keyword in string_value.lower()
                            for keyword in [
                                "key",
                                "token",
                                "secret",
                                "api",
                                "auth",
                                "password",
                            ]
                        )
                        or len(string_value) > 20
                    ):
                        all_strings_with_location.append(
                            {
                                "value": string_value,
                                "location": f"Smali const-string in {method_name}",
                                "file_path": f"{class_name}.smali",
                                "line_number": None,
                            }
                        )
                        strings_extracted += 1

                except (IndexError, AttributeError):
                    # Handle cases where string extraction fails
                    continue
        return strings_extracted

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
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

    def _has_required_context(self, string: str, required_keywords: list[str]) -> bool:
        """Check if string has required context keywords nearby."""
        string_lower = string.lower()

        # Simple context check - look for keywords in the string itself
        return any(keyword.lower() in string_lower for keyword in required_keywords)

    def _is_false_positive(self, string: str) -> bool:
        """Check for common false positives - enhanced to reduce noise from expanded patterns."""
        string_lower = string.lower()

        false_positives = self._build_false_positive_patterns(string, string_lower)

        for pattern in false_positives:
            if pattern and re.search(pattern, string_lower):
                return True

        # Additional heuristic checks
        # Skip very short strings for high-entropy patterns
        if len(string) < 16 and any(x in string_lower for x in ["entropy", "random", "base64"]):
            return True

        # Skip strings that are mostly numbers
        if len(string) > 8 and sum(c.isdigit() for c in string) / len(string) > 0.8:
            return True

        # Skip strings with too many special characters (likely encoded data, not keys)
        special_chars = sum(1 for c in string if not c.isalnum())
        return bool(len(string) > 20 and special_chars / len(string) > 0.3)

    def _build_false_positive_patterns(self, string: str, string_lower: str) -> list:
        """Build the list of common false-positive regex patterns."""
        return [
            # Android/Java class names and packages
            r"^(com|android|java|javax|kotlin|androidx)\.",
            r"\.class$",
            r"\.java$",
            r"\.kt$",
            r"\.xml$",
            r"\.png$",
            r"\.jpg$",
            r"\.so$",
            # Common placeholder values - expanded set
            r"^(test|example|sample|demo|placeholder|dummy)",
            r"^(your_api_key|your_token|your_secret|insert_key_here|api_key_here|replace_with)",
            r"^(null|undefined|none|nil|empty)$",
            r"(test|demo|sample|example).*(?:key|token|secret)",
            r"(fake|mock|stub).*",
            r"^xxx+$",
            r"^yyy+$",
            # Development/debugging strings
            r"^(debug|log|print|console)",
            r"lorem.*ipsum",
            r"hello.*world",
            # Repeated characters (unlikely to be real keys)
            r"^(.)\1{10,}$",
            r"^(a|b|c|x|y|z){20,}$",
            r"^(0123456789){2,}$",
            # URLs and domains - expanded
            r"^https?://",
            r"\.(?:com|org|net|edu|gov|mil|int|io|co\.uk|de|fr|jp)(?:/|$)",
            r"localhost",
            r"127\.0\.0\.1",
            r"0\.0\.0\.0",
            r"example\.com",
            r"test\.com",
            # Version strings and identifiers
            r"^\d+\.\d+",
            r"^v\d+",
            r"version.*\d+",
            # All zeros, ones or simple patterns
            r"^0+$",
            r"^1+$",
            r"^(abc|123|xyz|test){3,}$",
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            if string.count("-") == 4 and len(string) == 36 and "test" in string_lower
            else None,
            # Common configuration keys that aren't secrets
            r"^(true|false|enabled|disabled|yes|no)$",
            r"^\d+$",  # Pure numbers
            r"^[a-z]+$" if len(string) < 8 else None,  # Short all-lowercase strings
            # File paths and system strings
            r"^[\\/]",  # Starts with path separator
            r"\\x[0-9a-f]{2}",  # Hex escape sequences
            r"%[0-9a-f]{2}",  # URL encoding
            # Common Android/mobile development false positives - EXPANDED
            r"android.*",
            r"build.*config",
            r"manifest.*",
            r"application.*id",
            r"package.*name",
            r"^com\.google\.android\.gms",  # Google Play Services
            r"^androidx\.",  # AndroidX libraries
            r"activity|fragment|service|receiver|provider",  # Component types
            r"layout|drawable|string|color|dimen",  # Resource types
            # Base64 patterns that are likely not secrets
            r"^data:image",  # Data URLs
            r"iVBORw0KGgo",  # PNG header in base64
            r"/9j/",  # JPEG header in base64
            # Common Android SDK/NDK identifiers
            r"lib[a-z]+\.so",  # Native library names
            r"^[A-Z_]+_VERSION",  # Version constants
            r"^SDK_INT",
            r"^BUILD_",
        ]
