Configuration Guide
===================

Dexray Insight uses a YAML configuration file to control analysis behavior, external tool integration, and security assessment parameters. This guide provides comprehensive documentation for all configuration options.

Configuration File Structure
-----------------------------

The main configuration file is ``dexray.yaml``, which contains several top-level sections:

.. code-block:: yaml

   # Analysis execution settings
   analysis: {}
   
   # Module-specific configuration
   modules: {}
   
   # External tool configuration
   tools: {}
   
   # Temporal analysis directories
   temporal_analysis: {}
   
   # Security assessment settings
   security: {}
   
   # Output format and location
   output: {}
   
   # Logging configuration
   logging: {}

Loading Configuration
~~~~~~~~~~~~~~~~~~~~~

Configuration files can be loaded in several ways:

.. code-block:: bash

   # Use default dexray.yaml in current directory
   dexray-insight app.apk
   
   # Specify custom configuration file
   dexray-insight app.apk -c my_config.yaml
   
   # Use configuration with command-line overrides
   dexray-insight app.apk -c dexray.yaml -s --deep

**Priority Order** (highest to lowest):

1. Command-line arguments
2. Custom configuration file (``-c`` option)  
3. Default ``dexray.yaml`` in current directory
4. Built-in defaults

Analysis Configuration
----------------------

Controls overall analysis execution behavior:

.. code-block:: yaml

   analysis:
     parallel_execution:
       enabled: true          # Enable parallel module execution
       max_workers: 4         # Number of worker threads
     timeout:
       module_timeout: 300    # Timeout per module (seconds)
       tool_timeout: 600      # Timeout per external tool (seconds)

**Options**:

* ``parallel_execution.enabled``: Enable concurrent module execution for faster analysis
* ``parallel_execution.max_workers``: Number of parallel worker threads (default: 4)
* ``timeout.module_timeout``: Maximum time allowed per analysis module (default: 300s)
* ``timeout.tool_timeout``: Maximum time allowed per external tool (default: 600s)

Module Configuration  
--------------------

Controls which analysis modules are enabled and their specific settings:

Signature Detection Module
~~~~~~~~~~~~~~~~~~~~~~~~~~

Integrates with threat intelligence APIs to check APK signatures:

.. code-block:: yaml

   modules:
     signature_detection:
       enabled: true
       priority: 10
       providers:
         virustotal:
           enabled: false
           api_key: "YOUR_VIRUSTOTAL_API_KEY"
           rate_limit: 4  # requests per minute for free tier
         koodous:
           enabled: false
           api_key: "YOUR_KOODOUS_API_KEY"
         triage:
           enabled: false
           api_key: "YOUR_TRIAGE_API_KEY"

**Configuration Options**:

* ``enabled``: Enable/disable signature checking
* ``priority``: Execution priority (lower numbers run first)
* ``providers.*.enabled``: Enable specific threat intelligence providers
* ``providers.*.api_key``: API authentication keys
* ``virustotal.rate_limit``: Rate limiting for free tier accounts

Permission Analysis Module
~~~~~~~~~~~~~~~~~~~~~~~~~~

Analyzes Android permissions and identifies critical permissions:

.. code-block:: yaml

   modules:
     permission_analysis:
       enabled: true
       priority: 20
       critical_permissions_file: null  # Path to custom permissions file
       use_default_critical_list: true

**Configuration Options**:

* ``critical_permissions_file``: Path to custom critical permissions list
* ``use_default_critical_list``: Use built-in critical permissions database

String Analysis Module
~~~~~~~~~~~~~~~~~~~~~~

Extracts and analyzes strings from APK files:

.. code-block:: yaml

   modules:
     string_analysis:
       enabled: true
       priority: 30
       patterns:
         ip_addresses: true      # Extract IP address patterns
         urls: true             # Extract URL patterns
         email_addresses: true  # Extract email patterns  
         domains: true          # Extract domain patterns
         base64_strings: true   # Extract Base64 encoded strings
       filters:
         min_string_length: 2            # Minimum string length
         exclude_patterns: []            # Regex patterns to exclude

**Configuration Options**:

* ``patterns.*``: Enable/disable specific string pattern extraction
* ``filters.min_string_length``: Minimum length for extracted strings
* ``filters.exclude_patterns``: List of regex patterns to exclude from results

API Invocation Analysis Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Analyzes method calls and reflection usage (performance intensive):

.. code-block:: yaml

   modules:
     api_invocation:
       enabled: false  # Disabled by default due to performance
       priority: 40
       reflection_analysis: true  # Analyze reflection usage

**Configuration Options**:

* ``reflection_analysis``: Enable detection of reflection-based API calls

Manifest Analysis Module
~~~~~~~~~~~~~~~~~~~~~~~~

Analyzes AndroidManifest.xml components and configurations:

.. code-block:: yaml

   modules:
     manifest_analysis:
       enabled: true
       priority: 15
       extract_intent_filters: true      # Extract intent filter definitions
       analyze_exported_components: true # Analyze exported component security

**Configuration Options**:

* ``extract_intent_filters``: Parse and analyze intent filters
* ``analyze_exported_components``: Check for insecurely exported components

Tracker Analysis Module
~~~~~~~~~~~~~~~~~~~~~~~

Identifies third-party tracking libraries using Exodus Privacy database:

.. code-block:: yaml

   modules:
     tracker_analysis:
       enabled: true
       priority: 35
       fetch_exodus_trackers: true  # Fetch latest tracker database
       exodus_api_url: "https://reports.exodus-privacy.eu.org/api/trackers"
       api_timeout: 10

**Configuration Options**:

* ``fetch_exodus_trackers``: Download latest tracker signatures from Exodus
* ``exodus_api_url``: Exodus Privacy API endpoint
* ``api_timeout``: API request timeout (seconds)

Behavior Analysis Module
~~~~~~~~~~~~~~~~~~~~~~~~

Analyzes privacy-sensitive and advanced behavioral patterns:

.. code-block:: yaml

   modules:
     behaviour_analysis:
       enabled: true   # Enabled by default in fast mode
       priority: 1000  # Lowest priority - runs last
       deep_mode: false  # Use --deep flag to enable
       features:
         device_model_access: true           # Detect device model access
         imei_access: true                   # Detect IMEI access patterns
         android_version_access: true        # Detect OS version checks
         phone_number_access: true           # Detect phone number access
         clipboard_usage: true               # Detect clipboard operations
         dynamic_receivers: true             # Detect dynamic receiver registration
         camera_access: true                 # Detect camera usage
         running_services_access: true       # Detect service enumeration
         installed_applications_access: true # Detect app enumeration
         installed_packages_access: true     # Detect package enumeration
         reflection_usage: true              # Detect reflection usage

**Configuration Options**:

* ``deep_mode``: Enable comprehensive behavioral analysis (use ``--deep`` CLI flag)
* ``features.*``: Enable/disable specific behavioral detection patterns

Library Detection Module
~~~~~~~~~~~~~~~~~~~~~~~~

Identifies third-party libraries using heuristic and similarity analysis:

.. code-block:: yaml

   modules:
     library_detection:
       enabled: true
       priority: 25
       
       # Stage 1: Heuristic Detection
       enable_heuristic: true
       confidence_threshold: 0.7  # Minimum confidence for detections
       
       # Stage 2: Similarity Detection (LibScan-inspired)
       enable_similarity: true
       similarity_threshold: 0.85      # Minimum similarity score
       class_similarity_threshold: 0.7 # Individual class matching threshold
       
       # Custom library patterns
       custom_patterns: {}
       # Example:
       # custom_patterns:
       #   "My Custom Library":
       #     packages: ["com.example.mylibrary"]
       #     category: "utility"
       #     classes: ["MyLibraryMain", "MyLibraryHelper"] 
       #     permissions: ["android.permission.INTERNET"]
       
       # Analysis features
       features:
         package_analysis: true      # Analyze package names
         class_analysis: true        # Analyze class names and hierarchies
         manifest_analysis: true     # Check manifest elements
         method_analysis: true       # Analyze method signatures
         call_chain_analysis: true   # Analyze method relationships
         structural_analysis: true   # Compare dependency structures

**Configuration Options**:

* ``enable_heuristic``: Enable pattern-based heuristic detection
* ``confidence_threshold``: Minimum confidence score for heuristic matches
* ``enable_similarity``: Enable structural similarity analysis
* ``similarity_threshold``: Minimum similarity score for positive matches
* ``custom_patterns``: Define custom library detection patterns
* ``features.*``: Enable/disable specific analysis techniques

Native Analysis Module
~~~~~~~~~~~~~~~~~~~~~~

Analyzes native binaries (.so files) using Radare2:

.. code-block:: yaml

   modules:
     native_analysis:
       enabled: true
       priority: 50
       requires_temporal_analysis: true  # Only run when APK is unzipped
       
       # Architecture filtering
       architectures:
         - "arm64-v8a"      # Primary 64-bit ARM
         # - "armeabi-v7a"  # 32-bit ARM (enable if needed)
         # - "x86_64"       # 64-bit x86 (uncommon on mobile)
         # - "x86"          # 32-bit x86 (uncommon on mobile)
       
       # File filtering  
       file_patterns:
         - "*.so"           # Native shared libraries
         # - "*.a"          # Static libraries (uncommon in APKs)
         
       # Analysis modules
       modules:
         string_extraction:
           enabled: true
           min_string_length: 4        # Minimum string length
           max_string_length: 1024     # Maximum string length
           encoding: "utf-8"           # Primary encoding
           fallback_encodings: ["latin1", "ascii"]  # Fallback encodings

**Configuration Options**:

* ``requires_temporal_analysis``: Only run when APK is extracted to temporary directory
* ``architectures``: List of CPU architectures to analyze (performance optimization)
* ``file_patterns``: File patterns to match for native binary detection
* ``modules.string_extraction.*``: Configure native string extraction parameters

External Tools Configuration
-----------------------------

Configuration for external analysis tools:

APKTool Configuration
~~~~~~~~~~~~~~~~~~~~

For APK disassembly and resource extraction:

.. code-block:: yaml

   tools:
     apktool:
       enabled: true
       path: "/opt/homebrew/Cellar/apktool/2.12.0/libexec/apktool_2.12.0.jar"
       timeout: 600  # 10 minutes
       java_options: ["-Xmx2g"]  # Java heap options
       options: ["--no-debug-info"]

**Configuration Options**:

* ``path``: Full path to apktool JAR file
* ``timeout``: Maximum execution time (seconds)
* ``java_options``: JVM memory and runtime options
* ``options``: APKTool command-line options

JADX Configuration
~~~~~~~~~~~~~~~~~~

For Java decompilation (optional):

.. code-block:: yaml

   tools:
     jadx:
       enabled: false  # Disabled by default
       path: "/Users/danielbaier/Downloads/jadx-1.5.2/bin/jadx"
       timeout: 900  # 15 minutes
       options: ["--no-debug-info", "--no-inline-anonymous", "--show-bad-code"]

**Configuration Options**:

* ``path``: Full path to JADX executable
* ``timeout``: Maximum decompilation time (seconds)
* ``options``: JADX command-line options for decompilation quality

Radare2 Configuration
~~~~~~~~~~~~~~~~~~~~

For native binary analysis (optional):

.. code-block:: yaml

   tools:
     radare2:
       enabled: true
       path: null  # Uses system PATH if null
       timeout: 120  # 2 minutes per binary
       options: ["-2"]  # -2 for no stderr output

**Configuration Options**:

* ``path``: Full path to radare2 binary (null uses system PATH)
* ``timeout``: Maximum analysis time per binary (seconds)
* ``options``: Radare2 command-line options

Androguard Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Core Android analysis library:

.. code-block:: yaml

   tools:
     androguard:
       enabled: true
       logging_level: "WARNING"  # Reduce androguard log verbosity

**Configuration Options**:

* ``logging_level``: Set androguard's internal logging level

Temporal Analysis Configuration
-------------------------------

Controls temporary directory management for extracted APK contents:

.. code-block:: yaml

   temporal_analysis:
     enabled: true
     base_directory: "./temp_analysis"  # Base directory for analysis
     cleanup_after_analysis: false     # Keep files after analysis
     directory_structure:
       unzipped_folder: "unzipped"      # Unzipped APK contents
       jadx_folder: "jadxResults"       # JADX decompiled results
       apktool_folder: "apktoolResults" # Apktool results
       logs_folder: "logs"              # Tool execution logs
     preserve_on_error: true  # Keep directories if analysis fails

**Configuration Options**:

* ``enabled``: Enable creation of temporary analysis directories
* ``base_directory``: Root directory for temporary analysis files
* ``cleanup_after_analysis``: Automatically delete temporary directories after analysis
* ``directory_structure.*``: Configure subdirectory names for different tool outputs
* ``preserve_on_error``: Keep temporary files if analysis encounters errors (debugging)

Security Assessment Configuration
---------------------------------

Comprehensive OWASP Top 10 security assessment settings:

Core Security Settings
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   security:
     enable_owasp_assessment: false  # Enable via -s flag or set to true

Assessment Categories
~~~~~~~~~~~~~~~~~~~~

**Injection Vulnerability Detection**:

.. code-block:: yaml

   security:
     assessments:
       injection:
         enabled: true
         sql_patterns: ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]
         command_patterns: ["exec", "system", "runtime"]

**Broken Authentication**:

.. code-block:: yaml

   security:
     assessments:
       broken_authentication:
         enabled: true
         check_weak_crypto: true
         check_hardcoded_secrets: true

**Sensitive Data Exposure**:

.. code-block:: yaml

   security:
     assessments:
       sensitive_data:
         enabled: true
         pii_patterns: ["email", "phone", "ssn", "credit_card"]
         crypto_keys_check: true

Enhanced Secret Detection
~~~~~~~~~~~~~~~~~~~~~~~~~

Dexray Insight includes advanced hardcoded secret detection with **54 different patterns**:

.. code-block:: yaml

   security:
     assessments:
       sensitive_data:
         key_detection:
           enabled: true
           # Detection patterns by severity
           patterns:
             pem_keys: true              # PEM formatted private keys (CRITICAL)
             ssh_keys: true              # SSH public/private keys (MEDIUM)
             jwt_tokens: true            # JWT tokens (HIGH)
             api_keys: true              # Various API keys (HIGH)
             base64_keys: true           # Base64 encoded keys (LOW)
             hex_keys: true              # Hexadecimal keys (MEDIUM)
             database_connections: true  # Database URIs (MEDIUM)
             high_entropy_strings: true  # Generic high-entropy strings (LOW)
           
           # Entropy thresholds
           entropy_thresholds:
             min_base64_entropy: 4.0     # Base64 strings
             min_hex_entropy: 3.5        # Hex strings
             min_generic_entropy: 5.0    # Generic strings
           
           # String length filters
           length_filters:
             min_key_length: 16          # Minimum potential key length
             max_key_length: 512         # Maximum to avoid very long strings
           
           # Context detection
           context_detection:
             enabled: true               # Context-aware detection
             strict_mode: false          # Require context for all detections

**Secret Pattern Categories by Severity**:

* **CRITICAL (11 patterns)**: PEM keys, AWS credentials, GitHub tokens, Firebase keys
* **HIGH (22 patterns)**: Generic passwords/API keys, JWT tokens, service-specific credentials  
* **MEDIUM (13 patterns)**: Database URIs, cloud service URLs, SSH keys, crypto keys
* **LOW (8 patterns)**: Third-party tokens, Base64 strings, high-entropy strings

**Other Security Assessments**:

.. code-block:: yaml

   security:
     assessments:
       broken_access_control:
         enabled: true
         check_exported_components: true
         check_permissions: true
       
       security_misconfiguration:
         enabled: true
         check_debug_flags: true
         check_network_security: true
       
       vulnerable_components:
         enabled: true
         check_known_libraries: true
       
       insufficient_logging:
         enabled: true
         check_logging_practices: true

Output Configuration
--------------------

Controls analysis result output format and location:

.. code-block:: yaml

   output:
     format: "json"                    # Output format (currently only JSON)
     pretty_print: true                # Human-readable JSON formatting
     include_timestamps: true          # Include timestamps in output
     output_directory: "./results"     # Directory for result files
     filename_template: "dexray_{apk_name}_{timestamp}.json"

**Configuration Options**:

* ``format``: Output format (currently supports "json")
* ``pretty_print``: Enable human-readable JSON formatting with indentation
* ``include_timestamps``: Add timestamp metadata to results
* ``output_directory``: Directory where result files are saved
* ``filename_template``: Template for generating result filenames

**Template Variables**:

* ``{apk_name}``: Name of the analyzed APK file (without extension)
* ``{timestamp}``: Analysis timestamp in format YYYY-MM-DD_HH-MM-SS

Logging Configuration
---------------------

Controls logging behavior and output:

.. code-block:: yaml

   logging:
     level: "INFO"  # DEBUG, INFO, WARNING, ERROR
     format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
     file: null  # Log file path (null = console only)

**Configuration Options**:

* ``level``: Minimum log level to display (overridden by ``-d`` CLI flag)
* ``format``: Python logging format string
* ``file``: Path to log file (null sends logs to console only)

Configuration Examples
----------------------

Performance-Optimized Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For fast analysis of large APK batches:

.. code-block:: yaml

   analysis:
     parallel_execution:
       enabled: true
       max_workers: 8
     timeout:
       module_timeout: 180
       tool_timeout: 300

   modules:
     # Disable performance-intensive modules
     api_invocation:
       enabled: false
     behaviour_analysis:
       deep_mode: false
     
     # Limit native analysis architectures  
     native_analysis:
       architectures: ["arm64-v8a"]  # Only analyze primary architecture
     
     # Disable tracker fetching
     tracker_analysis:
       fetch_exodus_trackers: false

   logging:
     level: "WARNING"  # Reduce log verbosity

Security-Focused Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For comprehensive security analysis:

.. code-block:: yaml

   security:
     enable_owasp_assessment: true
     assessments:
       sensitive_data:
         key_detection:
           enabled: true
           patterns:
             pem_keys: true
             api_keys: true
             jwt_tokens: true
             database_connections: true
           entropy_thresholds:
             min_base64_entropy: 3.5  # More sensitive
             min_hex_entropy: 3.0
           context_detection:
             enabled: true
             strict_mode: true  # Require context

   modules:
     signature_detection:
       enabled: true
       providers:
         virustotal:
           enabled: true
           api_key: "YOUR_API_KEY"
     
     behaviour_analysis:
       enabled: true
       deep_mode: true  # Enable deep analysis

Research Configuration
~~~~~~~~~~~~~~~~~~~~~

For comprehensive analysis with all modules enabled:

.. code-block:: yaml

   modules:
     # Enable all analysis modules
     api_invocation:
       enabled: true
     behaviour_analysis:
       enabled: true
       deep_mode: true
     native_analysis:
       enabled: true
       architectures: ["arm64-v8a", "armeabi-v7a", "x86_64"]

   tools:
     # Enable all external tools
     jadx:
       enabled: true
     radare2:
       enabled: true

   temporal_analysis:
     cleanup_after_analysis: false  # Keep analysis files
     preserve_on_error: true

   logging:
     level: "DEBUG"  # Maximum verbosity
     file: "dexray_analysis.log"

Configuration Validation
-------------------------

Dexray Insight validates configuration files at startup. Common validation errors:

**Invalid YAML Syntax**:

.. code-block:: bash

   [-] Failed to load configuration file: invalid.yaml
   YAML parsing error: ...

**Missing Required Fields**:

.. code-block:: bash

   [-] Configuration validation failed
   Missing required configuration: analysis.parallel_execution

**Invalid Values**:

.. code-block:: bash

   [-] Configuration validation failed  
   Invalid timeout value: must be positive integer

**API Key Issues**:

.. code-block:: bash

   [W] VirusTotal API key not configured - signature detection disabled

Configuration Best Practices
-----------------------------

1. **Start with Default Configuration**: Copy and modify the included ``dexray.yaml``
2. **Use Environment-Specific Configs**: Separate configurations for development, testing, production
3. **Secure API Keys**: Store API keys in environment variables or secure configuration management
4. **Performance Tuning**: Adjust timeouts and parallel workers based on your hardware
5. **Logging Strategy**: Use appropriate log levels for different environments
6. **Regular Updates**: Keep external tool paths and configurations updated

**Environment Variables for API Keys**:

.. code-block:: bash

   export VIRUSTOTAL_API_KEY="your_key_here"
   export KOODOUS_API_KEY="your_key_here"

   # Reference in configuration:
   api_key: "${VIRUSTOTAL_API_KEY}"