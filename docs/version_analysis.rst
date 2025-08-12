Version Analysis
================

Overview
--------

Dexray Insight includes comprehensive version analysis capabilities that provide "years behind" calculations for detected libraries, helping identify security risks from outdated dependencies.

.. note::
   As of version 2024.2, **version analysis only runs during security analysis** by default. Use the ``-s`` flag to enable security analysis and version analysis together.

Features
--------

📚 **Library Version Analysis**
   - Semantic versioning support with proper parsing of various version formats
   - "Years behind" calculation showing how outdated detected libraries are  
   - Security risk assessment with CRITICAL/HIGH/MEDIUM/LOW classifications
   - Multiple version sources: Maven Central, Google Maven, npm, PyPI
   - Caching system to improve performance with configurable duration

🎯 **Google Maven Integration**
   - Specialized support for Google Play Services and Firebase libraries
   - 50+ library mappings for accurate Maven coordinate resolution
   - Fallback database with known versions for major Google libraries
   - XML metadata parsing from Google Maven repository

🔍 **Enhanced AndroidX Detection**
   - Corrected filtering logic using smali_path instead of library names
   - Finds 30+ AndroidX libraries vs. 8 with old logic
   - Comprehensive detection across multiple engines (Pattern, Heuristic, String Analysis)
   - Proper categorization with ANDROIDX category support

📺 **Enhanced Console Output**
   - Emoji indicators and visual risk level grouping
   - Detailed recommendations for each outdated library
   - Summary statistics showing total analysis results
   - Proper display order - appears after Library Detection summary

💾 **JSON Export Enhancement**
   - Complete version metadata in JSON output
   - All analysis fields included: years_behind, security_risk, recommendations
   - Structured data format for integration with other tools

Security-Only Analysis
-----------------------

Version analysis is designed as a security feature and only runs during security analysis by default:

**Enable Security Analysis (includes version analysis):**

.. code-block:: bash

   # Run with security analysis flag (enables version analysis)
   dexray-insight your-app.apk -s
   
   # With debug logging
   dexray-insight your-app.apk -s -d DEBUG

**Configuration Control:**

Version analysis can be controlled through configuration even within security analysis:

.. code-block:: yaml

   modules:
     library_detection:
       version_analysis:
         enabled: true                     # Enable/disable version analysis
         security_analysis_only: true     # Only run during security analysis (-s flag)
         api_timeout: 5                    # API timeout in seconds
         cache_duration_hours: 24          # Cache duration for version info

**Security Analysis Only vs. Always Available:**

- ``security_analysis_only: true`` (default): Version analysis only runs with ``-s`` flag
- ``security_analysis_only: false``: Version analysis runs in all analyses

Usage Examples
--------------

Basic Security Analysis with Version Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Basic security analysis (includes version analysis)
   dexray-insight your-app.apk -s
   
   # With specific configuration
   dexray-insight your-app.apk -s -c dexray.yaml -d DEBUG

Expected Output Format
~~~~~~~~~~~~~~~~~~~~~~

.. code-block::

   📚 LIBRARY VERSION ANALYSIS
   ================================================================================
   ⚠️  CRITICAL RISK LIBRARIES (3):
   ----------------------------------------
      Firebase Cloud Messaging (19.0.0): properties/firebase-messaging.properties: 6.0 years behind ⚠️ CRITICAL
      └─ Extremely outdated (6.0 years behind). Update immediately for security.
      
      Google Play Services Cast (19.0.0): properties/play-services-cast.properties: 3.2 years behind ⚠️ CRITICAL
      └─ Extremely outdated (3.2 years behind). Update immediately for security.

   ⚠️  HIGH RISK LIBRARIES (4):
   ----------------------------------------
      Firebase Components (16.1.0): properties/firebase-components.properties: 2.8 years behind ⚠️ HIGH RISK
      └─ Very outdated (2.8 years behind). High priority update recommended.

   📊 SUMMARY:
   ----------------------------------------
      Total libraries analyzed: 132
      Critical risk: 3
      High risk: 4  
      Average years behind: 1.2
   ================================================================================

Configuration
-------------

Complete Configuration Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   modules:
     library_detection:
       enabled: true
       priority: 25
       
       # Apktool-based detection (required for version analysis)
       apktool_detection:
         enable_pattern_detection: true     # Enable IzzyOnDroid pattern matching
         enable_properties_detection: true  # Enable .properties file analysis
         enable_buildconfig_detection: true # Enable BuildConfig.smali analysis
       
       # Version Analysis Configuration
       version_analysis:
         enabled: true                      # Enable "years behind" calculation
         security_analysis_only: true      # Only run during security analysis (-s flag)
         api_timeout: 5                     # API timeout in seconds
         cache_duration_hours: 24           # Cache API responses for 24 hours
         
         # Version sources (checked in order)
         sources:
           maven_central: true              # Check Maven Central for Java/Android libs
           npm_registry: true               # Check npm for JavaScript libraries
           pypi: true                       # Check PyPI for Python libraries (Kivy/BeeWare)
           custom_database: false           # Custom version database (extensible)
         
         # Console output configuration
         console_output:
           enabled: true                    # Show enhanced console output
           show_recommendations: true       # Show detailed update recommendations
           group_by_risk: true             # Group libraries by risk level
           show_summary: true              # Show summary statistics

Minimal Configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   modules:
     library_detection:
       version_analysis:
         enabled: true    # This enables all version analysis features with defaults

Testing
-------

Unit Tests
~~~~~~~~~~

.. code-block:: bash

   # Test version analysis core functionality
   python3 -m pytest tests/unit/modules/library_detection/test_version_analyzer.py -v
   
   # Test security-only version analysis logic
   python3 -m pytest tests/unit/modules/library_detection/test_version_analyzer.py -k "security" -v
   
   # Test AndroidX detection filtering
   python3 -m pytest tests/unit/modules/library_detection/test_androidx_detection.py -v

Integration Tests
~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Test complete pipeline with version analysis
   python3 -m pytest tests/integration/test_library_detection_version_analysis.py -v

Manual Testing
~~~~~~~~~~~~~~

.. code-block:: bash

   # Test security-only mode (should show version analysis)
   dexray-insight ./test-app.apk -s
   
   # Test without security flag (should NOT show version analysis)
   dexray-insight ./test-app.apk
   
   # Test with version analysis disabled even in security mode
   dexray-insight ./test-app.apk -s -c config_with_version_disabled.yaml

Technical Implementation
-----------------------

Key Components
~~~~~~~~~~~~~~

**VersionAnalyzer** (``utils/version_analyzer.py``)
   - Core analysis engine with semantic versioning support
   - Multiple API integrations (Maven Central, Google Maven, npm, PyPI)
   - Risk assessment algorithm based on age and major version differences
   - Security analysis context checking
   - Comprehensive caching system with configurable duration

**LibraryMappingRegistry** (``utils/library_mappings.py``)
   - 50+ Google library mappings from properties names to Maven coordinates
   - Category classification (messaging, location, analytics, etc.)
   - Display name normalization for consistent output

**ApktoolDetectionEngine** (``engines/apktool_detection_engine.py``)
   - Three detection approaches: Pattern matching, Properties scanning, BuildConfig analysis
   - Integrated version analysis for all detected libraries
   - Security analysis context awareness
   - Enhanced console output with proper formatting and risk indicators

**LibraryDetectionCoordinator** (``engines/coordinator.py``)
   - Display order management - ensures version analysis appears after library summary
   - Security analysis checking before displaying version results
   - Multi-engine coordination with proper AndroidX detection across all stages

Security Analysis Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Version analysis integrates with security analysis through:

1. **Configuration Check**: ``security_analysis_only`` setting in configuration
2. **Runtime Context**: Security analysis status passed through ``AnalysisContext``
3. **Conditional Execution**: Version analysis only runs when security analysis is enabled
4. **Display Control**: Console output only shows when appropriate conditions are met

Version Sources Priority Order
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Google Maven** (for Google Play Services, Firebase, AndroidX)
2. **Maven Central** (for general Java/Android libraries)
3. **npm registry** (for JavaScript libraries in hybrid apps)
4. **PyPI** (for Python libraries in Kivy/BeeWare apps)
5. **Known versions database** (fallback for major libraries)

Performance Metrics
-------------------

Detection Improvements
~~~~~~~~~~~~~~~~~~~~~~

- **AndroidX Libraries**: From 8 to 44+ libraries detected (450% improvement)
- **Total Libraries**: ~132 libraries vs. ~140 from detect_libs.py (98% parity)
- **Version Coverage**: 40+ libraries with version analysis in typical apps

Risk Assessment Distribution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Typical modern app distribution:

- **Critical Risk**: 3-5 libraries (3+ years behind)
- **High Risk**: 4-6 libraries (2+ years behind)  
- **Medium Risk**: 4-8 libraries (1+ years behind)
- **Low Risk**: 8-15 libraries (< 1 year behind)
- **Current**: 3-8 libraries (< 0.5 years behind)

Known Issues & Limitations
--------------------------

API Rate Limits
~~~~~~~~~~~~~~~

- Maven Central: No specific limits, but reasonable use expected
- Google Maven: No authentication required, but may have rate limits
- npm registry: No authentication required for public packages

Accuracy Considerations
~~~~~~~~~~~~~~~~~~~~~~~

- **Release date estimation**: When actual release dates unavailable, uses version difference heuristics
- **Version format variations**: Handles most common formats, but some proprietary formats may not parse correctly
- **Pre-release versions**: Properly identified and handled, but may affect age calculations

Configuration Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Apktool extraction required**: Version analysis only works with apktool-based detection enabled
- **Security analysis dependency**: Version analysis only runs during security analysis by default
- **Network connectivity**: Version checking requires internet access to API endpoints
- **Cache invalidation**: Long cache durations may result in slightly stale version information

Future Enhancements
-------------------

Potential Improvements
~~~~~~~~~~~~~~~~~~~~~~

- **CVE integration**: Link outdated versions to known vulnerabilities
- **Private repository support**: Support for enterprise Maven repositories
- **Batch API calls**: Improve performance with bulk version queries
- **Version trend analysis**: Track version update patterns over time
- **Custom risk thresholds**: User-configurable risk assessment criteria

Extension Points
~~~~~~~~~~~~~~~~

- **Custom version sources**: Easy to add new version databases/APIs
- **Custom risk algorithms**: Pluggable risk assessment strategies  
- **Custom output formats**: Additional export formats beyond JSON
- **Integration hooks**: Webhooks for CI/CD pipeline integration

References
----------

- `Semantic Versioning Specification <https://semver.org/>`_
- `Maven Central Search API <https://search.maven.org/classic/#api>`_
- `Google Maven Repository <https://maven.google.com/>`_
- `npm Registry API <https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md>`_
- `PyPI JSON API <https://warehouse.pypa.io/api-reference/json.html>`_