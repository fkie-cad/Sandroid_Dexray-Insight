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

New Security Assessments (v2)
-----------------------------

The v2 overhaul adds several focused assessments on top of the OWASP Mobile
Top 10 coverage. Unless noted otherwise they run on every ``-s`` security run
and are enabled by default in ``dexray.yaml``.

Verification Status and the Review Queue
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every finding now carries a ``verification_status`` that answers a different
question than ``confidence``: *is this a settled vulnerability, or a lead that
still needs runtime proof?*

* ``confirmed`` — a settled finding backed by concrete static evidence. Only
  confirmed findings (above the confidence threshold) drive the headline risk
  score.
* ``needs_dynamic`` — a real static signal whose *exploitability* depends on
  runtime state that static analysis cannot settle (IDOR/BOLA access control,
  RCE-pivot bridge surface, deep data-flow proximity hints). Surfaced as a
  ranked **review queue**, never reported as a confirmed vulnerability.
* ``needs_review`` — a low-confidence presence seed (a bare string-pool token or
  heuristic hit) that a human should triage.

Review-queue findings (``needs_dynamic`` / ``needs_review``) never inflate the
headline score. Their combined weight is reported separately as
``risk_score_review_mass`` so you can gauge how much unconfirmed signal exists
without it distorting the headline number.

.. code-block:: json

   {
       "title": "Possible IDOR / BOLA on exported content provider",
       "severity": "HIGH",
       "confidence": 0.6,
       "verification_status": "needs_dynamic",
       "description": "Static signal only — confirm exploitability at runtime."
   }

Privacy and PII Assessment (PRIVACY:2024)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A dedicated privacy assessment runs under a new
``PRIVACY:2024-Personal Data Exposure`` category, alongside the OWASP Mobile
Top 10. It replaces the old string-corpus PII scanner (which dumped library
placeholder e-mail addresses) with a validated PII taxonomy:

* **Validated literals** — credit-card numbers are confirmed with the Luhn
  checksum, phone numbers with E.164, US SSNs, and geolocation coordinates via
  range validators. A bare regex match alone is not reported.
* **Permission ↔ sink correlation** — a PII source is escalated only when the
  app both holds the matching permission and reaches a sink that could
  exfiltrate the data.
* **PII-at-rest** — ``CREATE TABLE`` column names and SharedPreferences keys are
  inspected for personal data, with a GDPR Art. 9 escalation for special
  categories, gated by the app's encryption posture.
* **Private-key-at-rest** — detection of private key material persisted on the
  device.
* **IDOR/BOLA review queue** — access-control leads that cannot be confirmed
  statically are emitted as ``needs_dynamic`` review-queue items.

.. code-block:: yaml

   security:
     assessments:
       pii:
         enabled: true   # PRIVACY:2024 taxonomy assessment (default on)

FileProvider Path-Scope Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``provider_paths`` assessment reads ``<provider>`` declarations and the
referenced ``res/xml/*_paths.xml`` files (via androguard) to flag misconfigured
``FileProvider`` scopes:

* Over-broad roots (e.g. sharing an entire external-storage or root path).
* Exported providers lacking signature-level permission protection.
* Duplicate authorities across providers.

.. code-block:: yaml

   security:
     assessments:
       provider_paths:
         enabled: true

SDK Risk-Surface Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``sdk_risk_surface`` assessment maps advertising/analytics SDKs to the risky
capabilities their concrete bridge classes expose (MRAID / VPAID / JavaScript
bridges, download-and-install flows). A finding is emitted per matched SDK when
the corresponding bridge-class descriptors are present in the APK — even when
the SDK version is unknown. These are surfaced as ``needs_review`` review-queue
items rather than confirmed RCE.

.. code-block:: yaml

   security:
     assessments:
       sdk_risk_surface:
         enabled: true

Deep Data-Flow and PII-Flow Assessments (``--deep`` only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two xref-based assessments run **only** under ``--deep`` (they are gated on
``modules.behaviour_analysis.deep_mode``):

* ``deep_dataflow`` — emits ``needs_dynamic`` proximity hints for
  intent-redirection, URI-to-WebView flows, IPC deserialization, provider
  ``openFile`` path traversal, and debuggable-gated control paths.
* ``pii_flow`` — correlates validated PII *sources* with per-tracker *sinks*
  (Crashlytics / Firebase / Branch); off-device transmission is escalated to
  HIGH.

All deep findings are ``needs_dynamic`` — they seed the review queue and never
enter the headline score. Because they rely on androguard cross-references, the
results are cached (keyed on the APK MD5 plus a schema version), so a second
``--deep`` run reuses them and skips the expensive ``create_xref()`` pass.

.. code-block:: yaml

   security:
     assessments:
       deep_dataflow:
         enabled: true   # runs only under --deep
       pii_flow:
         enabled: true   # runs only under --deep

Network Security Configuration: User Trust Anchors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The insecure-communication analysis now detects apps whose Network Security
Configuration trusts ``user``-installed CA certificates, which makes traffic
interception via a user-added certificate substantially easier.

Precision Improvements (v2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The v2 overhaul routes detections through validators that eliminate the most
common false positives:

* **Secret / entropy detection** rejects binary blobs, base64-image fragments,
  cryptographic test-vector hex, DEX class descriptors, slash paths, and
  camelCase code identifiers before a string is treated as a secret.
* **Weak-crypto** findings require a real ``getInstance``/usage context rather
  than a bare mention of an algorithm name.
* **SSRF / injection** findings require a first-party sink and are not raised on
  library or ad-SDK ``%s`` URL templates.
* **Dangerous-permission** severity is tiered: standard messenger permissions
  are LOW/informational, while genuine over-grants are HIGH.
* **Cleartext-URL** findings filter documentation, namespace, and placeholder
  hosts, keeping only first-party endpoints.

The precision layer only ever down-ranks or re-tiers findings for display; it
never deletes a raw finding from the JSON, so downstream tooling retains the
full data set.

Risk Assessment and Scoring
---------------------------

Confirmed-Subset Risk Scoring (v2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The headline ``overall_risk_score`` is the **confirmed-subset** score. Only
findings that are ``verification_status == confirmed`` **and** have
``confidence >= confirmed_threshold`` (default ``0.7``) enter the headline.
Review-queue findings never enter it. This makes the headline count-robust: a
flood of unconfirmed leads can no longer inflate the number, so the headline is
the defensible figure to threshold on.

Alongside the headline, the security results emit:

* ``risk_score_confirmed`` — the confirmed-subset score (the headline in the
  default mode).
* ``risk_score_review_mass`` — the combined weight of the review queue
  (``needs_dynamic`` / ``needs_review``), reported separately.
* ``overall_risk_score_raw`` — the sum-over-all-findings score.
* ``risk_score_legacy`` — the old v1 count-weighted score, emitted for
  migration.

**Monotonicity invariants**: adding a review-queue finding never changes the
headline, and adding a confirmed finding never lowers it.

**Per-severity diminishing returns.** The raw sum that feeds the base score now
applies *diminishing returns within each severity tier*. Findings are grouped by
severity, ranked by confidence, and the k-th finding in a tier (0-indexed by
descending confidence) contributes ``weight × confidence × decay**k``. This stops
a pile of same-severity findings — especially MEDIUM — from dominating the
headline by sheer count: the first few genuine findings in a tier count at (or
near) full weight, while the long tail is progressively discounted.

The decay factor is per-severity, configured under
``security.risk_scoring.severity_decay``. Defaults:

* ``critical: 1.0`` — undecayed, so a genuine critical still dominates.
* ``high: 0.8``
* ``medium: 0.5``
* ``low: 0.4``

**Soft additive critical bump.** The old hard "critical floor" (a single
confirmed CRITICAL clamped the headline to ``>= 75``) has been replaced by a
soft additive bump::

   score = min(100, base + critical_bump * n_confirmed_critical)

The default ``critical_bump`` is ``18.0``. This keeps the headline continuous
instead of binary. The legacy ``critical_floor`` knob remains readable for
rollback but is no longer applied as a clamp.

**Net effect.** Together, the per-severity decay and the recalibrated bump keep
the headline count-robust: a moderate app that accumulates many MEDIUM findings
now lands in a defensible band (for illustration, ~35-40 on the Kik ``base.apk``
benchmark) rather than being inflated by count alone, while malware whose score
is driven by genuine CRITICAL findings stays high and a benign app stays ~0.

**Configuration** (``dexray.yaml``):

.. code-block:: yaml

   security:
     risk_scoring:
       version: 2
       headline_mode: confirmed   # "raw" reverts to the old sum-over-all behaviour
       confirmed_threshold: 0.7   # min confidence for a confirmed finding to count
       critical_bump: 18.0        # soft additive bump per confirmed CRITICAL
       critical_floor: 75.0       # legacy; retained for rollback, no longer clamped
       severity_decay:            # per-severity diminishing-returns factor
         critical: 1.0            # undecayed — a genuine critical still dominates
         high: 0.8
         medium: 0.5
         low: 0.4

Legacy Risk Calculation (illustrative)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   The pseudo-code below illustrates the earlier count-weighted model. The
   default headline is now the confirmed-subset score described above. Set
   ``security.risk_scoring.headline_mode: raw`` to restore a sum-over-all
   headline.

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

CVE Vulnerability Scanning
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dexray Insight includes comprehensive CVE (Common Vulnerabilities and Exposures) scanning capabilities that automatically check detected libraries against online vulnerability databases.

**Supported CVE Data Sources**:

* **OSV (Open Source Vulnerabilities)** - Google's vulnerability database; key-less and the default backend
* **NVD (National Vulnerability Database)** - NIST's comprehensive CVE database (off by default; needs an API key)
* **GitHub Advisory Database** - GitHub's security advisory database (off by default; token recommended)

.. note::

   **Behavior change (v2).** CVE scanning is now **un-gated for Java/Android
   libraries** — previously it was native-only and, in practice, found nothing.
   Because ``cve_scanning.enabled`` defaults to ``true`` in the shipped
   ``dexray.yaml``, CVE scanning against OSV runs on **every** ``-s`` security
   run for any library that carries a detected version. This makes outbound
   network calls to the OSV API. To disable it, set
   ``security.cve_scanning.enabled: false`` (or trim
   ``security.cve_scanning.sources``).

**Data-source defaults**:

* **OSV** is enabled by default and requires no API key.
* **NVD** is disabled by default: without an API key it rate-limit-stalls. Set a
  real key and enable it to use NVD.
* **GitHub Advisory** is disabled by default; a token improves rate limits.

**Enabling CVE Scanning**:

CVE scanning is part of the security assessment. With the shipped configuration
it already runs under ``-s`` (OSV source). The ``--cve`` flag remains available
to force CVE scanning on and still requires security to be enabled (via ``-s``
or a config file):

.. code-block:: bash

   # Security assessment — CVE scanning against OSV runs by default
   dexray-insight app.apk -s

   # Explicitly force CVE scanning
   dexray-insight app.apk --sec --cve

   # With custom configuration
   dexray-insight app.apk --sec --cve -c dexray.yaml

**Configuration Options**:

.. code-block:: yaml

   security:
     cve_scanning:
       enabled: true  # Enabled by default; runs under -s (makes network calls)

       # CVE Data Sources
       sources:
         osv:  # Open Source Vulnerabilities (Google)
           enabled: true   # Key-less default backend (Java + native libraries)
           api_key: null   # OSV doesn't require an API key
         nvd:  # National Vulnerability Database (NIST)
           enabled: false  # Off by default: needs an API key
           api_key: "YOUR_NVD_API_KEY"
         github:  # GitHub Advisory Database
           enabled: false  # Off by default; token improves rate limits
           api_key: "YOUR_GITHUB_TOKEN"

       # Library type filtering
       scan_native_only: false       # Scan native AND Java/Android libraries
       include_java_libraries: true  # Java/Android libs scanned when they carry a version
       
       # Performance Configuration
       max_workers: 3  # Parallel CVE scans
       timeout_seconds: 30  # Timeout per API request
       min_confidence: 0.7  # Minimum library confidence for scanning
       max_libraries_per_source: 50  # Limit to avoid excessive API usage
       
       # Caching Configuration
       cache_duration_hours: 24  # Cache results for 24 hours
       cache_dir: null  # Default: ~/.dexray_insight/cve_cache

**CVE Scanning Process**:

1. **Library Extraction**: Identifies libraries with versions from library detection results
2. **Confidence Filtering**: Only scans libraries above the confidence threshold
3. **Parallel Scanning**: Queries multiple CVE databases simultaneously with rate limiting
4. **Deduplication**: Removes duplicate vulnerabilities based on CVE IDs
5. **Severity Classification**: Groups findings by CRITICAL, HIGH, MEDIUM, LOW severity
6. **Caching**: Stores results to avoid repeated API calls

**Example CVE Findings**:

.. code-block:: json

   {
       "cve_scanning": [
           {
               "title": "Critical CVE Vulnerabilities Detected",
               "severity": "CRITICAL",
               "description": "Application uses libraries with critical CVE vulnerabilities",
               "evidence": [
                   "CVE-2021-0341 (CVSS: 9.8): Certificate validation bypass in OkHttp",
                   "CVE-2019-12384 (CVSS: 9.1): Remote code execution in Jackson Databind"
               ],
               "recommendations": [
                   "URGENT: Address critical vulnerabilities immediately",
                   "Update affected libraries to patched versions",
                   "Consider temporarily disabling affected features if necessary"
               ]
           },
           {
               "title": "CVE Vulnerability Scan Summary", 
               "severity": "INFO",
               "description": "Found 15 vulnerabilities across 8 libraries",
               "evidence": [
                   "Total CVE vulnerabilities found: 15",
                   "Libraries scanned: 8",
                   "Critical: 2, High: 5, Medium: 6, Low: 2",
                   "CVE sources used: osv, nvd, github"
               ]
           }
       ]
   }

**Rate Limiting and Performance**:

CVE scanning includes intelligent rate limiting to respect API limits:

* **OSV**: 60 requests/minute (no API key required)
* **NVD**: 10 requests/minute (without API key), 100 requests/minute (with API key)
* **GitHub**: 60 requests/hour (without token), 5000 requests/hour (with token)

**API Keys Configuration**:

To improve rate limits and performance, configure API keys:

.. code-block:: yaml

   security:
     cve_scanning:
       sources:
         nvd:
           api_key: "your-nvd-api-key"  # Get from https://nvd.nist.gov/developers/request-an-api-key
         github:
           api_key: "your-github-token"  # Create at https://github.com/settings/tokens

**Caching and Performance**:

* Results are cached for 24 hours by default
* Cache location: ``~/.dexray_insight/cve_cache/``
* Cache statistics available in scan summary
* Automatic cache cleanup and optimization

**Integration with Library Detection**:

CVE scanning requires library detection to identify libraries with versions:

.. code-block:: yaml

   modules:
     library_detection:
       enabled: true
       # Version analysis helps identify exact library versions for CVE scanning
       version_analysis:
         enabled: true

**Troubleshooting CVE Scanning**:

Common issues and solutions:

* **No vulnerabilities found**: Library versions may not be detected accurately
* **API timeouts**: Increase ``timeout_seconds`` or enable fewer sources
* **Rate limiting**: Configure API keys for higher rate limits
* **Network errors**: Check internet connectivity and firewall settings

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