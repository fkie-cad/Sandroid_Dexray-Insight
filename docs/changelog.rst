Changelog
=========

All notable changes to Dexray Insight are documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_, 
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

[Unreleased]
------------

Added
~~~~~
- **Verification status** on every finding (``confirmed`` / ``needs_review`` /
  ``needs_dynamic``); unconfirmed static leads are surfaced as a ranked review queue
- **PII / privacy assessment** (``assessments.pii``) under a new
  ``PRIVACY:2024-Personal Data Exposure`` category, with a validated PII taxonomy
  (Luhn/E.164/SSN/geo validators, permission↔sink correlation, PII-at-rest with an
  encryption-posture gate, and private-key-at-rest detection)
- **FileProvider path-scope analyzer** (``assessments.provider_paths``): over-broad roots,
  exported providers without signature protection, duplicate authorities
- **SDK risk-surface** assessment (``assessments.sdk_risk_surface``) mapping ad-SDK bridge
  classes to risky capabilities
- **Deep data-flow** (``assessments.deep_dataflow``) and **PII-flow**
  (``assessments.pii_flow``) assessments that run only under ``--deep`` (xref-based, all
  ``needs_dynamic``); deep findings are cached (keyed on APK MD5 + schema version)
- NSC ``user``-trust-anchor detection (apps trusting user-installed CA certificates)
- New scoring fields: ``risk_score_confirmed``, ``risk_score_review_mass``,
  ``overall_risk_score_raw``, ``risk_score_legacy``, ``risk_score_version``
- Configurable risk scoring (``security.risk_scoring``): ``headline_mode``,
  ``confirmed_threshold``, ``critical_bump``, ``severity_decay``
- Comprehensive Sphinx documentation with RTD theme
- Complete API documentation for all modules and utilities
- Testing framework documentation with writing guides
- GitHub Actions workflow for automated documentation updates
- Enhanced security assessment with 54 secret detection patterns
- Native binary analysis using Radare2 integration
- Synthetic APK builder for testing
- Advanced configuration options in dexray.yaml
- Performance optimization settings

Changed
~~~~~~~
- **Headline risk score** is now the confirmed-subset score by default
  (``headline_mode: confirmed``): only ``confirmed`` findings with confidence ≥ 0.7 enter
  the headline; review-queue weight is reported separately as ``risk_score_review_mass``.
  Set ``headline_mode: raw`` to restore the old sum-over-all behaviour
- **Critical scoring** replaced the hard critical floor with a soft additive bump
  (``critical_bump``, default lowered 25.0 → 18.0); ``critical_floor`` is retained for
  rollback only
- **Risk-score recalibration**: the raw sum now applies per-severity diminishing returns.
  Within each severity tier, findings are ranked by confidence and the k-th contributes
  ``weight × confidence × decay**k`` (``severity_decay`` defaults ``critical: 1.0``,
  ``high: 0.8``, ``medium: 0.5``, ``low: 0.4``). This stops a pile of same-severity
  (especially MEDIUM) findings from inflating the headline by count — a moderate app now
  lands in a defensible band (~35-40 on the Kik ``base.apk`` benchmark) while
  critical-driven malware stays high and benign apps stay ~0
- **Analysis cache logic versioning**: added ``ANALYSIS_SCHEMA_VERSION``
  (``core/cache_manager.py``), folded into the full-result and per-module cache keys as
  the shallow-cache analog of the deep cache's ``DEEP_SCHEMA_VERSION``. Because the key is
  otherwise config-based and the fingerprint's ``tool_version`` does not move during
  in-place development, bumping it on a detection-logic change invalidates stale entries
  that would otherwise mask the change on re-analysis. Use ``--no-cache`` (or
  ``--clear-analysis-cache``) to force a fresh run when validating local changes
- **CVE scanning un-gated for Java/Android libraries** (previously native-only); OSV is
  the key-less default source and runs on every ``-s`` run (outbound network calls), NVD
  is off by default (needs an API key)
- A config file (``-c``) and CLI flags now **compose** — ``-s``, ``--cve``, ``--deep``,
  etc. override the config file instead of being dropped
- ``--deep`` now also enables ``modules.tracker_analysis.deep_string_location_analysis``
  for PII-flow attribution
- Improved native library extraction with fallback mechanisms
- Enhanced error handling across all modules
- Updated CLI interface with additional debugging options
- Refactored testing framework for better maintainability

Fixed
~~~~~
- **False-positive precision**: secret/entropy detection now rejects binary blobs,
  base64-image fragments, crypto test-vector hex, DEX class descriptors, slash paths, and
  camelCase identifiers; weak-crypto requires real ``getInstance``/usage context;
  SSRF/injection require first-party sinks (not library/ad-SDK URL templates);
  dangerous-permission severity is tiered; cleartext-URL findings filter
  documentation/namespace/placeholder hosts
- Native library detection showing framework names instead of .so files
- Configuration validation and error reporting
- Import errors in testing modules
- Linting issues across codebase

[1.0.0] - 2024-01-15
-------------------

Added
~~~~~

Core Framework
^^^^^^^^^^^^^^
- Object-oriented analysis architecture with modular design
- Configurable analysis engine with dependency resolution
- Parallel execution support for improved performance
- Comprehensive configuration system with YAML support
- Standardized result format with JSON export
- Temporal analysis with APK extraction capabilities

Analysis Modules
^^^^^^^^^^^^^^^^
- **APK Overview Module**: Package metadata, permissions, components, native libraries
- **String Analysis Module**: URL, IP, email, domain, and Base64 pattern extraction
- **Permission Analysis Module**: Android permission categorization and risk assessment
- **Signature Detection Module**: VirusTotal, Koodous, and Triage API integration
- **Manifest Analysis Module**: AndroidManifest.xml security analysis
- **Library Detection Module**: Third-party library identification with heuristic and similarity analysis
- **Tracker Analysis Module**: Privacy tracking library detection using Exodus database
- **Behavior Analysis Module**: Privacy-sensitive behavior detection with deep mode
- **Native Analysis Module**: Native binary analysis with Radare2 integration

Security Assessment
^^^^^^^^^^^^^^^^^^
- OWASP Mobile Top 10 security analysis framework
- Enhanced hardcoded secret detection with 54 patterns:
  
  - **CRITICAL (11 patterns)**: PEM keys, AWS credentials, GitHub tokens, Firebase keys
  - **HIGH (22 patterns)**: Generic passwords/API keys, JWT tokens, service credentials
  - **MEDIUM (13 patterns)**: Database URIs, cloud URLs, SSH keys, crypto keys  
  - **LOW (8 patterns)**: Third-party tokens, Base64 strings, high-entropy strings

- Context-aware detection with false positive reduction
- Entropy-based validation for encoded secrets
- Comprehensive remediation guidance

External Tool Integration
^^^^^^^^^^^^^^^^^^^^^^^^^
- **Androguard**: Core Android analysis functionality
- **APKTool**: APK disassembly and resource extraction
- **JADX**: Java decompilation support
- **Radare2**: Native binary analysis
- **VirusTotal API**: Malware detection
- **Koodous API**: Android-specific threat intelligence
- **Triage API**: Automated malware analysis

Framework Support
^^^^^^^^^^^^^^^^
- Native Android applications
- Flutter framework detection
- React Native framework detection
- Xamarin framework detection
- Unity framework detection
- Cordova/PhoneGap framework detection

Command Line Interface
^^^^^^^^^^^^^^^^^^^^^
- Comprehensive CLI with multiple analysis options
- Debug logging with configurable levels
- Verbose output modes
- Custom configuration file support
- Parallel execution control
- Security assessment toggle
- Signature detection integration
- Deep behavioral analysis mode

Testing Framework
^^^^^^^^^^^^^^^^
- pytest-based testing infrastructure
- Synthetic APK generation for reproducible tests
- Comprehensive fixture system
- Unit tests for core utilities and base classes
- Integration tests for module interactions
- Mock objects for external dependencies
- Performance and stress testing capabilities
- GitHub Actions CI/CD integration

Documentation
^^^^^^^^^^^^
- Comprehensive Sphinx documentation
- API reference with autodoc integration
- User guides and tutorials
- Configuration documentation
- Testing framework guides
- Contributing guidelines
- Security assessment documentation

Docker Support
^^^^^^^^^^^^^
- Containerized analysis environment
- Multi-stage Docker build
- External tool integration in container
- Volume mounting for APK analysis

Changed
~~~~~~~
- Migrated from procedural to object-oriented architecture
- Replaced individual analysis scripts with unified framework
- Improved error handling and reporting
- Enhanced configuration management
- Standardized logging across all modules

Security
~~~~~~~~
- Enhanced secret detection with context awareness
- Improved OWASP Mobile Top 10 coverage
- Advanced behavioral analysis capabilities
- Threat intelligence integration
- Vulnerability scoring and risk assessment

Performance
~~~~~~~~~~
- Parallel module execution support
- Configurable timeouts and resource limits
- Optimized native library detection
- Improved memory management for large APKs
- Caching support for expensive operations

[0.9.0] - 2023-12-01
-------------------

Added
~~~~~
- Initial modular architecture design
- Basic APK analysis capabilities
- String extraction functionality
- Permission analysis module
- Configuration system prototype

[0.8.0] - 2023-11-15
-------------------

Added
~~~~~
- Core analysis engine foundation
- Androguard integration
- Basic CLI interface
- JSON output format

[0.7.0] - 2023-11-01
-------------------

Added
~~~~~
- Initial project structure
- Basic APK parsing capabilities
- Proof of concept analysis modules

Migration Guide
---------------

From 0.9.x to 1.0.0
~~~~~~~~~~~~~~~~~~

**Configuration Changes**:

Old format:
.. code-block:: yaml

   analysis_modules:
     string_analysis: true
     permission_analysis: true

New format:
.. code-block:: yaml

   modules:
     string_analysis:
       enabled: true
       priority: 10
     permission_analysis:
       enabled: true
       priority: 20

**CLI Changes**:

.. code-block:: bash

   # Old command
   python asam.py app.apk --security --debug
   
   # New command  
   dexray-insight app.apk -s -d DEBUG

**Result Format Changes**:

The JSON output structure has been standardized with consistent field names and hierarchical organization.

From Legacy Scripts to 1.0.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Replace individual analysis scripts with the unified framework:

.. code-block:: bash

   # Replace multiple commands
   python string_analyzer.py app.apk
   python permission_checker.py app.apk
   python security_scanner.py app.apk
   
   # With single command
   dexray-insight app.apk -s

Deprecation Notices
------------------

**Deprecated in 1.0.0**:
- Legacy command-line interfaces (will be removed in 2.0.0)
- Old configuration format (migrate to YAML)
- Individual analysis script execution

**Planned for Removal in 2.0.0**:
- Python 3.7 support (minimum Python 3.8)
- Legacy result format compatibility
- Deprecated CLI flags

Breaking Changes
---------------

Version 1.0.0
~~~~~~~~~~~~~
- **Configuration Format**: New YAML-based configuration system
- **CLI Interface**: Unified command structure with new flags
- **Result Format**: Standardized JSON output with new field names
- **Python Version**: Minimum Python 3.8 required
- **Dependencies**: Updated Androguard and other core dependencies

Upgrade Instructions
-------------------

To upgrade to the latest version:

.. code-block:: bash

   # Backup existing configuration and results
   cp dexray_config.json dexray_config.json.backup
   
   # Install latest version
   pip install --upgrade dexray-insight
   
   # Migrate configuration
   dexray-insight --migrate-config dexray_config.json.backup
   
   # Verify installation
   dexray-insight --version
   dexray-insight sample.apk --dry-run

For detailed upgrade instructions and migration assistance, see the `Migration Guide <#migration-guide>`_.

Known Issues
------------

- Large APKs (>100MB) may require increased timeout values
- Some external tools may not be available on all platforms
- Native analysis requires Radare2 installation for full functionality
- Performance may vary significantly based on APK complexity and size

For the most up-to-date list of known issues, see the `GitHub Issues <https://github.com/fkie-cad/Sandroid_Dexray-Insight/issues>`_ page.