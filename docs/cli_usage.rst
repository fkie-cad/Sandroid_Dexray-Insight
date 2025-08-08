Command Line Interface
======================

Dexray Insight provides a comprehensive command-line interface for analyzing Android APK files. This guide covers all available options and usage patterns.

Basic Usage
-----------

The basic syntax for Dexray Insight is:

.. code-block:: bash

   dexray-insight <path_to_apk> [options]

**Simple Analysis Example**:

.. code-block:: bash

   dexray-insight MyApp.apk

This performs a standard static analysis including:

* APK overview and metadata extraction
* Permission analysis
* String analysis (IPs, URLs, emails, domains)
* Manifest component analysis
* Third-party library detection
* Tracker analysis (if enabled)

Command Line Options
--------------------

Target APK
~~~~~~~~~~

The first argument is always the path to the target APK file:

.. code-block:: bash

   dexray-insight /path/to/application.apk
   dexray-insight ./MyApp.apk
   dexray-insight ~/Downloads/sample.apk

Logging and Debug Options
~~~~~~~~~~~~~~~~~~~~~~~~~

``-d, --debug [LEVEL]``
   Set the logging level for debugging output.
   
   **Options**: ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``
   
   **Default**: ``ERROR``
   
   **Examples**:
   
   .. code-block:: bash
   
      # Enable INFO level logging
      dexray-insight app.apk -d INFO
      
      # Enable DEBUG level logging (most verbose)
      dexray-insight app.apk -d DEBUG
      
      # Use default INFO level
      dexray-insight app.apk -d

``-f, --filter FILE [FILE ...]``
   Filter log messages by specific source files. Useful for debugging specific modules.
   
   **Example**:
   
   .. code-block:: bash
   
      # Filter logs from specific modules
      dexray-insight app.apk -d DEBUG -f string_analysis.py api_invocation.py

``-v, --verbose``
   Enable verbose output. Shows complete JSON results instead of the analyst-friendly summary.
   
   **Example**:
   
   .. code-block:: bash
   
      # Show full JSON output
      dexray-insight app.apk -v

Analysis Control Options
~~~~~~~~~~~~~~~~~~~~~~~~

``-sig, --signaturecheck``
   Perform signature analysis using configured threat intelligence APIs.
   
   Requires API keys configured in ``dexray.yaml`` for:
   
   * VirusTotal
   * Koodous  
   * Triage
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight app.apk -sig

``-s, --sec``
   Enable OWASP Top 10 security analysis. This comprehensive assessment includes:
   
   * Injection vulnerability patterns
   * Broken authentication checks
   * Sensitive data exposure detection (54 secret patterns)
   * Broken access control analysis
   * Security misconfiguration detection
   * Vulnerable component identification
   * Insufficient logging analysis
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight app.apk -s

``-a, --api-invocation``
   Enable API invocation analysis. Analyzes method calls and reflection usage.
   
   **Disabled by default** due to performance impact.
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight app.apk -a

``--deep``
   Enable deep behavioral analysis. Detects privacy-sensitive behaviors and advanced techniques:
   
   * Device model access
   * IMEI access patterns
   * Android version detection
   * Phone number access
   * Clipboard usage
   * Dynamic receiver registration
   * Camera access patterns
   * Running services enumeration
   * Installed applications/packages access
   * Reflection usage analysis
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight app.apk --deep

Tracker Analysis Options
~~~~~~~~~~~~~~~~~~~~~~~~

``-t, --tracker``
   Explicitly enable tracker analysis (enabled by default in configuration).
   
   Uses Exodus Privacy database to identify tracking libraries.
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight app.apk -t

``--no-tracker``
   Disable tracker analysis even if enabled in configuration.
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight app.apk --no-tracker

Diffing and Comparison
~~~~~~~~~~~~~~~~~~~~~

``--diffing_apk <path_to_diff_apk>``
   Specify an additional APK for comparison and diffing analysis.
   
   **Example**:
   
   .. code-block:: bash
   
      # Compare two APK versions
      dexray-insight app-v1.apk --diffing_apk app-v2.apk

.NET Analysis Options
~~~~~~~~~~~~~~~~~~~~

``--exclude_net_libs <path_to_file>``
   Specify which .NET libraries/assemblies should be ignored during analysis.
   
   Provide a path to a file containing library names (comma or newline separated).
   
   **Example**:
   
   .. code-block:: bash
   
      # Exclude system libraries
      echo "System.Security,Microsoft.Framework" > exclude_libs.txt
      dexray-insight app.apk --exclude_net_libs exclude_libs.txt

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

``-c, --config <config_file>``
   Path to custom configuration file (JSON or YAML format).
   
   **Example**:
   
   .. code-block:: bash
   
      # Use custom configuration
      dexray-insight app.apk -c my_config.yaml
      
      # Use configuration with security assessment
      dexray-insight app.apk -c dexray.yaml -s

Information Options
~~~~~~~~~~~~~~~~~~~

``--version``
   Display the current version of Dexray Insight and exit.
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight --version

``--help, -h``
   Show help message with all available options.
   
   **Example**:
   
   .. code-block:: bash
   
      dexray-insight --help

Usage Patterns
--------------

Common Analysis Scenarios
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Basic Security Assessment**:

.. code-block:: bash

   # Comprehensive security analysis
   dexray-insight app.apk -s -d INFO

**Threat Intelligence Integration**:

.. code-block:: bash

   # Check against threat feeds
   dexray-insight app.apk -sig -c dexray.yaml

**Deep Privacy Analysis**:

.. code-block:: bash

   # Analyze privacy-sensitive behaviors
   dexray-insight app.apk --deep --no-tracker -v

**Performance-Oriented Analysis**:

.. code-block:: bash

   # Fast analysis without heavy modules
   dexray-insight app.apk --no-tracker -d WARNING

**Development and Debugging**:

.. code-block:: bash

   # Full debugging with specific module focus
   dexray-insight app.apk -d DEBUG -f string_analysis.py -v

**APK Version Comparison**:

.. code-block:: bash

   # Compare two APK versions
   dexray-insight new_app.apk --diffing_apk old_app.apk -s

Combined Options Examples
~~~~~~~~~~~~~~~~~~~~~~~~~

**Complete Security Analysis**:

.. code-block:: bash

   dexray-insight suspicious_app.apk -s -sig --deep -d INFO -c dexray.yaml

This command performs:

* OWASP Top 10 security assessment (``-s``)
* Signature checking with threat intelligence (``-sig``) 
* Deep behavioral analysis (``--deep``)
* INFO level logging (``-d INFO``)
* Custom configuration (``-c dexray.yaml``)

**Researcher Analysis**:

.. code-block:: bash

   dexray-insight research_sample.apk -a --deep -v -d DEBUG

This command performs:

* API invocation analysis (``-a``)
* Deep behavioral analysis (``--deep``)
* Verbose JSON output (``-v``)
* Debug logging (``-d DEBUG``)

**Production Batch Analysis**:

.. code-block:: bash

   # Script-friendly analysis with minimal output
   dexray-insight batch_sample.apk -s --no-tracker -d ERROR

Output Control
--------------

Analysis Results
~~~~~~~~~~~~~~~~

**Default Output**: Analyst-friendly summary displayed to terminal

**With ``-v`` Flag**: Complete JSON results displayed to terminal

**File Output**: Results always saved to timestamped JSON files:

* ``dexray_{apk_name}_{timestamp}.json`` - Main analysis results
* ``dexray_{apk_name}_security_{timestamp}.json`` - Security assessment results (if ``-s`` used)

**Output Location**: Current working directory by default (configurable in ``dexray.yaml``)

Exit Codes
----------

Dexray Insight returns different exit codes based on execution results:

* ``0`` - Analysis completed successfully
* ``1`` - Analysis failed due to error
* ``2`` - Missing or invalid arguments
* ``130`` - Analysis interrupted by user (Ctrl+C)

**Example in Scripts**:

.. code-block:: bash

   #!/bin/bash
   dexray-insight app.apk -s
   if [ $? -eq 0 ]; then
       echo "Analysis completed successfully"
   else
       echo "Analysis failed with exit code $?"
       exit 1
   fi

Error Handling
--------------

Common Error Scenarios
~~~~~~~~~~~~~~~~~~~~~~

**APK File Not Found**:

.. code-block:: bash

   $ dexray-insight nonexistent.apk
   [-] APK file not found: nonexistent.apk

**Configuration File Errors**:

.. code-block:: bash

   $ dexray-insight app.apk -c invalid.yaml
   [-] Failed to load configuration file: invalid.yaml

**Permission Errors**:

.. code-block:: bash

   # Fix with proper permissions
   chmod +r app.apk
   dexray-insight app.apk

**Memory Issues with Large APKs**:

.. code-block:: bash

   # Use configuration to limit memory usage
   dexray-insight large_app.apk -c memory_optimized.yaml

Advanced Usage
--------------

Integration with Scripts
~~~~~~~~~~~~~~~~~~~~~~~

**Bash Integration**:

.. code-block:: bash

   #!/bin/bash
   
   APK_DIR="/path/to/apks"
   RESULTS_DIR="/path/to/results"
   
   for apk in "$APK_DIR"/*.apk; do
       echo "Analyzing: $apk"
       dexray-insight "$apk" -s -d INFO
       
       # Move results to organized directory
       mv dexray_*.json "$RESULTS_DIR/"
   done

**Python Integration**:

.. code-block:: python

   import subprocess
   import sys
   
   def analyze_apk(apk_path, config_path=None):
       cmd = ['dexray-insight', apk_path, '-s']
       if config_path:
           cmd.extend(['-c', config_path])
       
       result = subprocess.run(cmd, capture_output=True, text=True)
       return result.returncode == 0

Environment Variables
~~~~~~~~~~~~~~~~~~~~

Dexray Insight respects several environment variables:

.. code-block:: bash

   # Set default configuration path
   export DEXRAY_CONFIG_PATH="/etc/dexray/dexray.yaml"
   
   # Set default output directory
   export DEXRAY_OUTPUT_DIR="/var/log/dexray"
   
   # Disable colored output for scripts
   export NO_COLOR=1

Performance Tuning
~~~~~~~~~~~~~~~~~~

For large-scale analysis:

.. code-block:: bash

   # Limit resource usage
   dexray-insight app.apk -s --no-tracker -d WARNING
   
   # Use custom timeouts in configuration
   dexray-insight app.apk -c fast_analysis.yaml
   
   # Process multiple APKs in parallel (external)
   parallel -j 4 dexray-insight {} -s ::: *.apk