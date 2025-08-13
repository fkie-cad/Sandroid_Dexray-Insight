Security Assessment
===================

Dexray Insight provides comprehensive security analysis based on the OWASP Mobile Top 10, enhanced with 54 different secret detection patterns and advanced behavioral analysis. This guide covers the security assessment capabilities, configuration options, and interpretation of findings.

OWASP Mobile Top 10 Coverage
-----------------------------

The security assessment (enabled with ``-s`` flag) covers all OWASP Mobile Top 10 categories:

M1: Improper Platform Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Misuse of platform features or security controls
* Insecure inter-app communication
* Improper use of Android permissions
* Violation of Android security best practices

**Analysis Methods**:

* Manifest analysis for component security
* Permission usage patterns
* Intent filter security validation
* API usage pattern analysis

**Example Findings**:

.. code-block:: json

   {
       "category": "M1-Improper-Platform-Usage",
       "findings": [
           {
               "title": "Exported Activity Without Permission Protection",
               "severity": "MEDIUM",
               "description": "MainActivity is exported but lacks permission protection",
               "evidence": {
                   "component": "com.example.MainActivity",
                   "exported": true,
                   "permission": null,
                   "intent_filters": ["android.intent.action.MAIN"]
               },
               "remediation": "Add permission requirement or set android:exported='false'"
           }
       ]
   }

M2: Insecure Data Storage
~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Hardcoded secrets and API keys (54 different patterns)
* Sensitive data in SharedPreferences
* Database security issues
* External storage vulnerabilities

**Secret Detection Patterns**:

**CRITICAL Severity (11 patterns)**:
- PEM-formatted private keys (RSA, DSA, EC, OpenSSH, PGP)
- AWS credentials with context detection
- GitHub Personal Access Tokens and Fine-grained tokens
- Google OAuth tokens and GCP Service Account credentials
- Firebase Cloud Messaging keys
- Passwords in URLs

**HIGH Severity (22 patterns)**:
- Generic passwords, API keys, and secrets with smart context matching
- JWT tokens with proper Base64 validation
- Service-specific credentials for Azure, Heroku, Stripe, Discord, GitLab
- Facebook, Twitter, MailChimp, Mailgun tokens
- Square, Amazon MWS credentials
- Slack tokens and authorization headers

**MEDIUM Severity (13 patterns)**:
- Database connection URIs (MongoDB, PostgreSQL, MySQL, Redis)
- Cloud service URLs (Cloudinary, Firebase, Slack webhooks)
- SSH public keys and certificates
- Google Cloud API keys
- Hex-encoded cryptographic keys (128-bit, 256-bit)

**LOW Severity (8 patterns)**:
- Third-party service tokens (Jenkins, PayPal Braintree, Google Captcha)
- S3 bucket URLs
- Base64 encoded strings with entropy analysis
- High-entropy strings that may indicate encoded secrets

**Configuration**:

.. code-block:: yaml

   security:
     assessments:
       sensitive_data:
         key_detection:
           enabled: true
           patterns:
             pem_keys: true              # CRITICAL
             ssh_keys: true              # MEDIUM
             jwt_tokens: true            # HIGH
             api_keys: true              # HIGH
             base64_keys: true           # LOW
             hex_keys: true              # MEDIUM
             database_connections: true  # MEDIUM
             high_entropy_strings: true  # LOW
           entropy_thresholds:
             min_base64_entropy: 4.0
             min_hex_entropy: 3.5
             min_generic_entropy: 5.0
           length_filters:
             min_key_length: 16
             max_key_length: 512
           context_detection:
             enabled: true
             strict_mode: false

**Example Secret Detection**:

.. code-block:: json

   {
       "category": "M2-Insecure-Data-Storage", 
       "findings": [
           {
               "title": "🔑 CRITICAL: AWS Access Key Detected",
               "severity": "CRITICAL",
               "secret_type": "AWS Access Key ID",
               "value": "AKIAIOSFODNN7EXAMPLE",
               "location": {
                   "file": "ConfigManager.java",
                   "line": 156,
                   "context": "private static final String AWS_KEY = \"AKIA...\";"
               },
               "entropy": 4.2,
               "confidence": 0.98,
               "remediation": [
                   "Remove hardcoded AWS credentials immediately",
                   "Use AWS SDK credential providers",
                   "Store credentials in secure configuration service",
                   "Rotate compromised credentials"
               ]
           }
       ]
   }

M3: Insecure Communication
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* HTTP traffic analysis
* TLS/SSL configuration issues
* Certificate pinning validation
* Network security configuration analysis

**Analysis Methods**:

* URL pattern analysis for HTTP vs HTTPS
* Network security config parsing
* Certificate validation in code
* Domain reputation analysis

M4: Insecure Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Weak authentication mechanisms
* Hardcoded passwords and credentials
* Biometric authentication issues
* Session management problems

**Example Findings**:

.. code-block:: json

   {
       "category": "M4-Insecure-Authentication",
       "findings": [
           {
               "title": "🚨 CRITICAL: Hardcoded Admin Password",
               "severity": "CRITICAL",
               "description": "Administrator password found hardcoded in source",
               "evidence": {
                   "value": "admin_password123",
                   "location": "AuthManager.java:89",
                   "context": "String adminPass = \"admin_password123\";"
               },
               "remediation": [
                   "Remove hardcoded password immediately",
                   "Implement secure authentication flow",
                   "Use proper credential storage",
                   "Add multi-factor authentication"
               ]
           }
       ]
   }

M5: Insufficient Cryptography
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Weak encryption algorithms
* Poor key management
* Cryptographic implementation flaws
* Random number generation issues

**Analysis Methods**:

* Cryptographic API usage analysis
* Key size and algorithm validation
* Entropy analysis of generated values
* Deprecated crypto library detection

M6: Insecure Authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Permission model violations
* Access control bypass vulnerabilities
* Privilege escalation opportunities
* Component exposure analysis

**Example Analysis**:

.. code-block:: json

   {
       "category": "M6-Insecure-Authorization",
       "findings": [
           {
               "title": "Exported Service Without Permission",
               "severity": "HIGH",
               "description": "Critical service exposed without proper authorization",
               "evidence": {
                   "component": "com.example.PrivilegedService",
                   "exported": true,
                   "permission": null,
                   "actions": ["ADMIN_ACTION", "DATA_ACCESS"]
               }
           }
       ]
   }

M7: Client Code Quality
~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Code obfuscation analysis
* Debug information exposure
* Runtime manipulation vulnerabilities
* Anti-tampering mechanism evaluation

M8: Code Tampering
~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Binary protection analysis
* Anti-debugging detection
* Runtime application self-protection (RASP)
* Integrity verification mechanisms

M9: Reverse Engineering
~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Obfuscation effectiveness analysis
* String encryption evaluation
* Control flow obfuscation detection
* Symbol stripping verification

M10: Extraneous Functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Detection Capabilities**:

* Debug functionality in release builds
* Test endpoints in production
* Development tools and backdoors
* Unused permission analysis

Advanced Security Features
-------------------------

Strategy Pattern Architecture for Secret Detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dexray Insight's secret detection system has been refactored using the Strategy Pattern to improve maintainability, extensibility, and testability. The detection process is now organized into five focused strategies:

**Strategy Pattern Workflow**:

.. code-block:: python

   def _assess_crypto_keys_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
       # Strategy 1: String Collection
       string_collector = StringCollectionStrategy(self.logger)
       all_strings = string_collector.collect_strings(analysis_results)
       
       # Strategy 2: Deep Analysis Enhancement
       deep_analyzer = DeepAnalysisStrategy(self.logger)
       enhanced_strings = deep_analyzer.extract_deep_strings(analysis_results, all_strings)
       
       # Strategy 3: Pattern Detection
       pattern_detector = PatternDetectionStrategy(self.detection_patterns, self.logger)
       detected_secrets = pattern_detector.detect_secrets(enhanced_strings)
       
       # Strategy 4: Result Classification
       result_classifier = ResultClassificationStrategy()
       classified_results = result_classifier.classify_by_severity(detected_secrets)
       
       # Strategy 5: Finding Generation
       finding_generator = FindingGenerationStrategy(self.owasp_category)
       return finding_generator.generate_security_findings(classified_results)

**String Collection Strategy**: Systematically gathers strings from multiple sources including string analysis results, Android properties, and raw DEX strings with location metadata.

**Deep Analysis Strategy**: Enhances string collection by extracting additional strings from DEX objects, XML resources, and Smali code when deep analysis mode is enabled.

**Pattern Detection Strategy**: Applies 54 different secret detection patterns across four severity levels using comprehensive pattern matching algorithms.

**Result Classification Strategy**: Organizes detected secrets by severity and creates both terminal display formats and structured evidence entries for JSON export.

**Finding Generation Strategy**: Creates final SecurityFinding objects with secret-finder style messaging and comprehensive remediation guidance.

Enhanced Secret Detection with Secret-Finder Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The refactored system maintains secret-finder style detection with enhanced accuracy:

**Smart Context Detection**:

.. code-block:: python

   # Context-aware API key detection
   "google_api_key_pattern": {
       "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
       "context_required": ["api", "key", "google", "maps"],
       "entropy_threshold": 4.0,
       "severity": "HIGH"
   }

**False Positive Reduction**:

.. code-block:: yaml

   security:
     assessments:
       sensitive_data:
         key_detection:
           context_detection:
             enabled: true
             strict_mode: false          # Allow detections without context
           filters:
             exclude_test_patterns: true # Exclude test/mock data
             exclude_examples: true      # Exclude documentation examples
             min_confidence: 0.7         # Minimum detection confidence

**Entropy-Based Validation**:

High-entropy strings are analyzed for potential encoded secrets:

.. code-block:: json

   {
       "secret_type": "High Entropy String", 
       "value": "dGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIHRlc3Rpbmc",
       "entropy": 5.2,
       "possible_encoding": "base64",
       "decoded_preview": "this is a secret key for testing",
       "severity": "MEDIUM",
       "confidence": 0.85
   }

Behavioral Security Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Advanced behavioral pattern detection (enabled with ``--deep`` flag):

**Privacy-Sensitive Behaviors**:

.. code-block:: json

   {
       "behavioral_analysis": {
           "privacy_violations": [
               {
                   "behavior": "Location Access Without User Consent",
                   "severity": "HIGH",
                   "evidence": {
                       "methods": ["getLastKnownLocation", "requestLocationUpdates"],
                       "permissions": ["ACCESS_FINE_LOCATION"],
                       "user_consent_check": false
                   }
               },
               {
                   "behavior": "Contact Data Harvesting",
                   "severity": "HIGH", 
                   "evidence": {
                       "methods": ["getAllContacts", "bulkContactQuery"],
                       "data_exfiltration": true,
                       "network_transmission": "https://analytics.suspicious-domain.com"
                   }
               }
           ]
       }
   }

**Advanced Evasion Techniques**:

.. code-block:: json

   {
       "evasion_techniques": [
           {
               "technique": "Dynamic Class Loading",
               "risk": "HIGH",
               "description": "Application loads code dynamically to evade static analysis",
               "evidence": {
                   "methods": ["DexClassLoader", "PathClassLoader"],
                   "dynamic_sources": ["external storage", "network"]
               }
           },
           {
               "technique": "Reflection-Based API Calls",
               "risk": "MEDIUM", 
               "description": "Uses reflection to hide sensitive API calls",
               "evidence": {
                   "reflected_methods": ["getSystemService", "getDeviceId"],
                   "obfuscated_strings": true
               }
           }
       ]
   }

Risk Assessment and Scoring
---------------------------

Overall Risk Calculation
~~~~~~~~~~~~~~~~~~~~~~~

Risk levels are calculated based on multiple factors:

.. code-block:: python

   def calculate_risk_level(findings):
       score = 0
       
       # Severity weights
       severity_weights = {
           'CRITICAL': 10,
           'HIGH': 7,
           'MEDIUM': 4,
           'LOW': 1
       }
       
       # Calculate base score
       for finding in findings:
           score += severity_weights.get(finding['severity'], 0)
       
       # Risk modifiers
       if has_hardcoded_secrets(findings):
           score *= 1.5
       
       if has_dangerous_permissions(findings): 
           score *= 1.2
           
       if has_network_exposure(findings):
           score *= 1.3
       
       # Determine risk level
       if score >= 50:
           return 'CRITICAL'
       elif score >= 30:
           return 'HIGH'
       elif score >= 15:
           return 'MEDIUM'
       else:
           return 'LOW'

**Risk Assessment Output**:

.. code-block:: json

   {
       "risk_assessment": {
           "overall_risk_level": "HIGH",
           "risk_score": 42,
           "contributing_factors": [
               {
                   "factor": "Hardcoded Secrets",
                   "impact": "HIGH", 
                   "count": 3,
                   "score_contribution": 15
               },
               {
                   "factor": "Dangerous Permissions",
                   "impact": "MEDIUM",
                   "count": 5,
                   "score_contribution": 8
               },
               {
                   "factor": "Network Security Issues",
                   "impact": "MEDIUM",
                   "count": 2,
                   "score_contribution": 6
               }
           ],
           "recommendations": [
               "Immediately address all CRITICAL and HIGH severity findings",
               "Implement secure credential management",
               "Review and minimize dangerous permissions",
               "Enable network security config"
           ]
       }
   }

Security Report Generation
-------------------------

Analyst-Friendly Reports
~~~~~~~~~~~~~~~~~~~~~~~

Security findings are presented in multiple formats:

**Executive Summary**:

.. code-block:: text

   🛡️ SECURITY ASSESSMENT REPORT
   
   📱 Application: MyApp v1.2.3 (com.example.myapp)
   📅 Analysis Date: 2024-01-15 10:30:45
   ⚠️  Overall Risk: HIGH
   
   🚨 CRITICAL FINDINGS (2):
   • AWS Access Key hardcoded in source code
   • Admin password stored in plain text
   
   ⚠️  HIGH FINDINGS (5):
   • 3 API keys detected in resources
   • 2 exported components without protection
   
   📊 SECURITY METRICS:
   • Secret Detection: 8 secrets found (54 patterns checked)
   • Permission Risk: 5 dangerous permissions
   • Component Security: 3 insecure components
   • Network Security: 2 HTTP endpoints detected

**Detailed Technical Report**:

Comprehensive JSON output with evidence, remediation steps, and technical details for security teams.

**Compliance Report**:

OWASP Mobile Top 10 compliance checklist with pass/fail status for each category.

Integration with Security Tools
-------------------------------

SIEM Integration
~~~~~~~~~~~~~~~

Export security findings in formats suitable for Security Information and Event Management systems:

.. code-block:: python

   def export_to_siem(results, format='json'):
       """Export security findings for SIEM integration"""
       
       siem_events = []
       
       if results.security_assessment:
           for finding in results.security_assessment.owasp_findings:
               event = {
                   'timestamp': datetime.utcnow().isoformat(),
                   'event_type': 'mobile_app_security_finding',
                   'severity': finding['severity'].lower(),
                   'category': finding['category'], 
                   'app_package': results.apk_overview.package_name,
                   'app_version': results.apk_overview.version_name,
                   'finding_title': finding['title'],
                   'description': finding['description'],
                   'evidence': finding.get('evidence', {}),
                   'remediation': finding.get('recommendations', [])
               }
               siem_events.append(event)
       
       return siem_events

Vulnerability Management Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Export findings in Common Vulnerability Scoring System (CVSS) format:

.. code-block:: json

   {
       "vulnerability": {
           "id": "DEXRAY-2024-001",
           "title": "Hardcoded AWS Credentials",
           "description": "AWS access credentials found hardcoded in application source",
           "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
           "cvss_score": 9.3,
           "severity": "CRITICAL",
           "cwe": "CWE-798",
           "owasp_mobile": "M2-Insecure-Data-Storage",
           "affected_component": "com.example.ConfigManager",
           "remediation_effort": "LOW",
           "business_impact": "HIGH"
       }
   }

Threat Intelligence Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Correlate findings with threat intelligence feeds:

.. code-block:: python

   def correlate_with_threat_intel(findings, threat_feeds):
       """Correlate security findings with threat intelligence"""
       
       correlations = []
       
       for finding in findings:
           if finding['type'] == 'hardcoded_secret':
               # Check against compromised credential databases
               if is_credential_compromised(finding['value']):
                   correlations.append({
                       'finding_id': finding['id'],
                       'threat_type': 'compromised_credential',
                       'severity': 'CRITICAL',
                       'action': 'immediate_rotation_required'
                   })
           
           elif finding['type'] == 'network_endpoint':
               # Check against malicious domain databases
               domain = extract_domain(finding['url'])
               reputation = get_domain_reputation(domain)
               
               if reputation['risk_score'] > 7:
                   correlations.append({
                       'finding_id': finding['id'],
                       'threat_type': 'malicious_domain',
                       'reputation_score': reputation['risk_score'],
                       'action': 'block_communication'
                   })
       
       return correlations

Best Practices for Security Assessment
-------------------------------------

Configuration Recommendations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**For Development Teams**:

.. code-block:: yaml

   security:
     enable_owasp_assessment: true
     assessments:
       sensitive_data:
         key_detection:
           enabled: true
           strict_mode: false    # Allow some false positives for comprehensive coverage
           patterns:
             # Enable all pattern categories
             pem_keys: true
             api_keys: true
             jwt_tokens: true
             database_connections: true
             high_entropy_strings: true

**For Security Teams**:

.. code-block:: yaml

   security:
     enable_owasp_assessment: true
     assessments:
       sensitive_data:
         key_detection:
           enabled: true
           strict_mode: true     # Require context for higher accuracy
           entropy_thresholds:
             min_base64_entropy: 4.5  # Higher threshold for fewer false positives
             min_hex_entropy: 4.0
           context_detection:
             enabled: true
             require_context: true

**For Automated Scanning**:

.. code-block:: yaml

   security:
     enable_owasp_assessment: true
     assessments:
       # Focus on high-confidence, automatable checks
       sensitive_data:
         key_detection:
           patterns:
             pem_keys: true      # High confidence patterns only
             api_keys: true
             jwt_tokens: false   # May have false positives
             high_entropy_strings: false

Remediation Guidance
~~~~~~~~~~~~~~~~~~~

Each security finding includes specific remediation guidance:

**Immediate Actions (CRITICAL/HIGH)**:
- Remove hardcoded secrets immediately
- Rotate compromised credentials
- Fix exported component vulnerabilities
- Address network security issues

**Short-term Actions (MEDIUM)**:
- Implement secure credential storage
- Add permission justifications
- Enable network security config
- Review component security settings

**Long-term Actions (LOW)**:
- Implement comprehensive security testing
- Add runtime application self-protection
- Regular security assessment integration
- Security awareness training for developers

The security assessment provides actionable insights to improve application security posture and comply with industry best practices and regulatory requirements.