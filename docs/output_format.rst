Output Format
=============

Dexray Insight generates comprehensive analysis results in JSON format with detailed metadata and structured findings. This guide explains the output format, data structures, and how to interpret results.

JSON Output Structure
---------------------

Standard Output Files
~~~~~~~~~~~~~~~~~~~~~

Dexray Insight generates timestamped JSON files in the following format:

.. code-block:: bash

   # Main analysis results
   dexray_{apk_name}_{timestamp}.json
   
   # Security assessment results (when -s flag is used)
   dexray_{apk_name}_security_{timestamp}.json

**Example Output Files**:

.. code-block:: text

   dexray_MyApp_2024-01-15_10-30-45.json
   dexray_MyApp_security_2024-01-15_10-30-45.json

Root JSON Structure
~~~~~~~~~~~~~~~~~~

The main analysis result follows this structure:

.. code-block:: json

   {
       "analysis_metadata": {
           "dexray_version": "1.0.0",
           "analysis_timestamp": "2024-01-15T10:30:45Z",
           "analysis_duration_seconds": 45.2,
           "apk_file_path": "/path/to/MyApp.apk",
           "apk_file_size_bytes": 12457600,
           "configuration_used": {
               "parallel_execution_enabled": true,
               "security_assessment_enabled": false,
               "modules_executed": ["apk_overview", "string_analysis", "permission_analysis"]
           }
       },
       "apk_overview": { /* APK metadata and components */ },
       "string_analysis": { /* Extracted strings and patterns */ },
       "permission_analysis": { /* Permission analysis results */ },
       "signature_detection": { /* Threat intelligence results */ },
       "manifest_analysis": { /* AndroidManifest.xml analysis */ },
       "library_detection": { /* Third-party library identification */ },
       "tracker_analysis": { /* Tracking library detection */ },
       "behaviour_analysis": { /* Behavioral analysis results */ },
       "native_analysis": { /* Native binary analysis */ },
       "security_assessment": { /* OWASP Top 10 security findings */ }
   }

Analysis Metadata
-----------------

Every analysis result includes comprehensive metadata:

.. code-block:: json

   {
       "analysis_metadata": {
           "dexray_version": "1.0.0",
           "analysis_timestamp": "2024-01-15T10:30:45Z",
           "analysis_duration_seconds": 45.2,
           "apk_file_path": "/path/to/MyApp.apv",
           "apk_file_size_bytes": 12457600,
           "apk_hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
           "apk_hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
           "apk_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "configuration_used": {
               "parallel_execution_enabled": true,
               "max_workers": 4,
               "security_assessment_enabled": false,
               "signature_detection_enabled": false,
               "modules_executed": [
                   "apk_overview",
                   "string_analysis", 
                   "permission_analysis",
                   "manifest_analysis",
                   "library_detection",
                   "tracker_analysis"
               ],
               "execution_times": {
                   "apk_overview": 2.1,
                   "string_analysis": 8.4,
                   "permission_analysis": 0.8,
                   "manifest_analysis": 1.2,
                   "library_detection": 15.6,
                   "tracker_analysis": 3.2
               }
           },
           "analysis_environment": {
               "python_version": "3.9.7",
               "platform": "Linux",
               "architecture": "x86_64",
               "androguard_version": "3.4.0"
           }
       }
   }

APK Overview Results
--------------------

Basic APK information and components:

.. code-block:: json

   {
       "apk_overview": {
           "module_name": "apk_overview",
           "status": "SUCCESS",
           "execution_time": 2.1,
           "package_name": "com.example.myapp",
           "version_name": "1.2.3",
           "version_code": 10203,
           "min_sdk_version": 21,
           "target_sdk_version": 30,
           "compile_sdk_version": 30,
           "app_name": "My Application",
           "permissions": [
               "android.permission.INTERNET",
               "android.permission.ACCESS_NETWORK_STATE",
               "android.permission.CAMERA",
               "android.permission.WRITE_EXTERNAL_STORAGE"
           ],
           "activities": [
               {
                   "name": "com.example.myapp.MainActivity",
                   "exported": true,
                   "intent_filters": ["android.intent.action.MAIN"]
               },
               {
                   "name": "com.example.myapp.SettingsActivity", 
                   "exported": false,
                   "intent_filters": []
               }
           ],
           "services": [
               {
                   "name": "com.example.myapp.BackgroundService",
                   "exported": false,
                   "permission": null
               }
           ],
           "receivers": [
               {
                   "name": "com.example.myapp.BootReceiver",
                   "exported": true,
                   "intent_filters": ["android.intent.action.BOOT_COMPLETED"]
               }
           ],
           "providers": [],
           "native_libraries": [
               "libexample.so",
               "libcrypto.so",
               "libssl.so"
           ],
           "framework": "Native",
           "certificates": [
               {
                   "subject": "CN=Example Developer, O=Example Corp",
                   "issuer": "CN=Example Developer, O=Example Corp", 
                   "serial_number": "1234567890",
                   "not_before": "2023-01-01T00:00:00Z",
                   "not_after": "2033-01-01T00:00:00Z",
                   "signature_algorithm": "SHA256withRSA",
                   "fingerprint_md5": "ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
                   "fingerprint_sha1": "12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78",
                   "fingerprint_sha256": "ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef"
               }
           ]
       }
   }

String Analysis Results
-----------------------

Extracted strings categorized by pattern type:

.. code-block:: json

   {
       "string_analysis": {
           "module_name": "string_analysis",
           "status": "SUCCESS",
           "execution_time": 8.4,
           "total_strings_analyzed": 2847,
           "urls": [
               {
                   "url": "https://api.example.com/v1",
                   "scheme": "https",
                   "domain": "api.example.com",
                   "path": "/v1",
                   "confidence": 0.95
               },
               {
                   "url": "http://analytics.tracking.com/collect",
                   "scheme": "http",
                   "domain": "analytics.tracking.com", 
                   "path": "/collect",
                   "confidence": 0.98
               }
           ],
           "ip_addresses": [
               {
                   "ip": "192.168.1.1",
                   "version": "IPv4",
                   "type": "private",
                   "confidence": 1.0
               },
               {
                   "ip": "8.8.8.8",
                   "version": "IPv4", 
                   "type": "public",
                   "confidence": 1.0
               }
           ],
           "email_addresses": [
               {
                   "email": "contact@example.com",
                   "domain": "example.com",
                   "confidence": 0.92
               }
           ],
           "domains": [
               {
                   "domain": "api.example.com",
                   "tld": "com",
                   "subdomain": "api",
                   "confidence": 0.98
               }
           ],
           "base64_strings": [
               {
                   "encoded": "dGVzdCBzdHJpbmc=",
                   "decoded": "test string",
                   "entropy": 3.2,
                   "confidence": 0.89
               }
           ],
           "patterns_summary": {
               "urls_count": 15,
               "ip_addresses_count": 8,
               "email_addresses_count": 3,
               "domains_count": 12,
               "base64_strings_count": 5
           }
       }
   }

Permission Analysis Results
---------------------------

Android permission analysis with categorization:

.. code-block:: json

   {
       "permission_analysis": {
           "module_name": "permission_analysis",
           "status": "SUCCESS", 
           "execution_time": 0.8,
           "total_permissions": 12,
           "permissions_by_category": {
               "dangerous": [
                   {
                       "permission": "android.permission.CAMERA",
                       "protection_level": "dangerous",
                       "permission_group": "android.permission-group.CAMERA",
                       "description": "Required to access camera hardware",
                       "risk_level": "HIGH"
                   },
                   {
                       "permission": "android.permission.ACCESS_FINE_LOCATION",
                       "protection_level": "dangerous", 
                       "permission_group": "android.permission-group.LOCATION",
                       "description": "Allows precise location access",
                       "risk_level": "HIGH"
                   }
               ],
               "normal": [
                   {
                       "permission": "android.permission.INTERNET",
                       "protection_level": "normal",
                       "description": "Allows network communication"
                   }
               ],
               "signature": [],
               "system": [],
               "custom": [
                   {
                       "permission": "com.example.myapp.CUSTOM_PERMISSION",
                       "protection_level": "unknown",
                       "description": "Custom application permission"
                   }
               ]
           },
           "risk_assessment": {
               "overall_risk": "MEDIUM",
               "high_risk_permissions": 2,
               "privacy_sensitive_permissions": 3,
               "recommendations": [
                   "Review necessity of camera permission",
                   "Consider using coarse location instead of fine location",
                   "Document custom permission usage"
               ]
           }
       }
   }

Security Assessment Results
---------------------------

OWASP Top 10 security analysis (when enabled with ``-s`` flag):

.. code-block:: json

   {
       "security_assessment": {
           "module_name": "security_assessment",
           "status": "SUCCESS",
           "execution_time": 18.7,
           "overall_risk_level": "HIGH",
           "total_vulnerabilities": 8,
           "vulnerability_breakdown": {
               "CRITICAL": 1,
               "HIGH": 3,
               "MEDIUM": 3,
               "LOW": 1
           },
           "owasp_top_10_findings": [
               {
                   "category": "M2-Insecure-Data-Storage",
                   "title": "Hardcoded API Keys Detected",
                   "severity": "HIGH",
                   "description": "Multiple API keys found hardcoded in application strings",
                   "evidence": [
                       {
                           "type": "Google API Key",
                           "value": "AIzaSyDexampleGoogleAPIkey***", 
                           "location": "strings.xml:line 42",
                           "confidence": 0.98
                       },
                       {
                           "type": "AWS Access Key",
                           "value": "AKIAIOSFODNN7EXAMPLE***",
                           "location": "ConfigManager.java:line 156",
                           "confidence": 0.95
                       }
                   ],
                   "recommendations": [
                       "Remove hardcoded API keys from source code",
                       "Use secure configuration management",
                       "Implement runtime key retrieval"
                   ]
               }
           ],
           "hardcoded_secrets": [
               {
                   "secret_type": "Google API Key",
                   "pattern_matched": "google_api_key",
                   "value": "AIzaSyDexampleGoogleAPIkey123456789",
                   "severity": "HIGH", 
                   "entropy": 4.8,
                   "location": {
                       "file": "strings.xml",
                       "line": 42,
                       "context": "<string name=\"api_key\">AIzaSyD...</string>"
                   },
                   "remediation": "Store API keys securely using Android Keystore or remote configuration"
               },
               {
                   "secret_type": "Hardcoded Password",
                   "pattern_matched": "password",
                   "value": "admin_password123", 
                   "severity": "CRITICAL",
                   "entropy": 3.2,
                   "location": {
                       "file": "AuthManager.java",
                       "line": 156,
                       "context": "String defaultPass = \"admin_password123\";"
                   },
                   "remediation": "Remove hardcoded passwords and implement proper authentication"
               }
           ],
           "secret_detection_summary": {
               "total_secrets_found": 12,
               "by_severity": {
                   "CRITICAL": 1,
                   "HIGH": 4,
                   "MEDIUM": 5,
                   "LOW": 2
               },
               "by_type": {
                   "API Keys": 6,
                   "Passwords": 3,
                   "Certificates": 2,
                   "Tokens": 1
               }
           }
       }
   }

Signature Detection Results
---------------------------

Threat intelligence integration results (when enabled with ``-sig`` flag):

.. code-block:: json

   {
       "signature_detection": {
           "module_name": "signature_detection",
           "status": "SUCCESS",
           "execution_time": 12.3,
           "file_hashes": {
               "md5": "d41d8cd98f00b204e9800998ecf8427e",
               "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
               "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
           },
           "virustotal": {
               "scan_performed": true,
               "scan_date": "2024-01-15T10:35:00Z",
               "total_engines": 70,
               "positive_detections": 3,
               "detection_ratio": "3/70",
               "permalink": "https://virustotal.com/analysis/abcd1234",
               "detected_threats": [
                   {
                       "engine": "Avira",
                       "result": "Android.Trojan.Banker",
                       "version": "8.3.3.14",
                       "update": "20240115"
                   },
                   {
                       "engine": "Kaspersky",
                       "result": "Trojan.AndroidOS.Boogr.gsh",
                       "version": "21.0.1.45",
                       "update": "20240115"
                   }
               ],
               "clean_engines": 67
           },
           "koodous": {
               "scan_performed": true,
               "detected": false,
               "rating": 2,
               "analysis_url": "https://koodous.com/analysis/example123",
               "community_votes": {
                   "positive": 1,
                   "negative": 8
               }
           },
           "overall_threat_assessment": {
               "risk_level": "MEDIUM",
               "is_likely_malware": false,
               "confidence": 0.15,
               "recommendations": [
                   "Low detection rate suggests possible false positives",
                   "Manual analysis recommended for suspicious behaviors",
                   "Monitor for behavioral indicators"
               ]
           }
       }
   }

Library Detection Results
-------------------------

Third-party library identification:

.. code-block:: json

   {
       "library_detection": {
           "module_name": "library_detection",
           "status": "SUCCESS",
           "execution_time": 15.6,
           "total_libraries_detected": 8,
           "detection_methods_used": ["heuristic", "similarity"],
           "libraries": [
               {
                   "name": "OkHttp",
                   "category": "networking",
                   "version": "4.9.3",
                   "confidence": 0.96,
                   "detection_method": "heuristic_package_analysis",
                   "evidence": {
                       "packages": ["okhttp3", "okio"],
                       "classes": ["OkHttpClient", "Request", "Response"],
                       "methods": ["newCall", "execute", "enqueue"]
                   },
                   "description": "HTTP client library for Android and Java",
                   "website": "https://square.github.io/okhttp/",
                   "license": "Apache-2.0"
               },
               {
                   "name": "Gson",
                   "category": "serialization",
                   "version": "2.8.9",
                   "confidence": 0.92,
                   "detection_method": "heuristic_class_analysis",
                   "evidence": {
                       "packages": ["com.google.gson"],
                       "classes": ["Gson", "JsonElement", "JsonParser"]
                   },
                   "description": "JSON serialization library for Java",
                   "website": "https://github.com/google/gson"
               }
           ],
           "categories_summary": {
               "networking": 2,
               "serialization": 1,
               "image_processing": 1,
               "analytics": 3,
               "ui": 1
           },
           "confidence_distribution": {
               "high_confidence": 5,
               "medium_confidence": 2,
               "low_confidence": 1
           }
       }
   }

Native Analysis Results
-----------------------

Native binary analysis results (when enabled and available):

.. code-block:: json

   {
       "native_analysis": {
           "module_name": "native_analysis",
           "status": "SUCCESS",
           "execution_time": 8.9,
           "radare2_available": true,
           "analyzed_binaries": [
               {
                   "file_path": "lib/arm64-v8a/libexample.so",
                   "relative_path": "lib/arm64-v8a/libexample.so",
                   "architecture": "arm64-v8a",
                   "file_size": 245760,
                   "file_name": "libexample.so"
               },
               {
                   "file_path": "lib/arm64-v8a/libcrypto.so", 
                   "relative_path": "lib/arm64-v8a/libcrypto.so",
                   "architecture": "arm64-v8a",
                   "file_size": 1843200,
                   "file_name": "libcrypto.so"
               }
           ],
           "total_strings_extracted": 127,
           "strings_by_source": {
               "lib/arm64-v8a/libexample.so": [
                   {
                       "content": "https://api.native-service.com",
                       "source_type": "native_binary",
                       "extraction_method": "r2_iz_data_sections",
                       "offset": 8192,
                       "confidence": 0.9
                   },
                   {
                       "content": "debug_mode_enabled",
                       "source_type": "native_binary", 
                       "extraction_method": "r2_izz_all_sections",
                       "offset": 12288,
                       "confidence": 0.8
                   }
               ]
           },
           "architectures_analyzed": ["arm64-v8a"],
           "binary_analysis_summary": {
               "total_binaries": 2,
               "successful_analyses": 2,
               "failed_analyses": 0,
               "strings_per_binary": {
                   "libexample.so": 45,
                   "libcrypto.so": 82
               }
           }
       }
   }

Output Formatting Options
-------------------------

Console Output Modes
~~~~~~~~~~~~~~~~~~~~

**Default Mode** (Analyst Summary):

.. code-block:: text

   📱 APK Analysis Report
   Package: com.example.myapp
   Version: 1.2.3 (10203)
   Framework: Native

   🛡️ Security Assessment: MEDIUM RISK
      Vulnerabilities Found: 3
      🔑 Hardcoded Secrets: 2

   📊 Analysis Summary:
      • Permissions: 12 (3 dangerous)
      • Components: 15 activities, 2 services
      • Libraries: 8 detected
      • Native Libraries: 3

   ⏱️ Analysis completed in 45.2 seconds
   Results saved to: dexray_MyApp_2024-01-15_10-30-45.json

**Verbose Mode** (``-v`` flag):

Shows complete JSON output to terminal in addition to file output.

**Debug Mode** (``-d DEBUG`` flag):

Includes detailed execution logs and timing information for each module.

File Output Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Configure output location and format in ``dexray.yaml``:

.. code-block:: yaml

   output:
     format: "json"                    # Output format
     pretty_print: true                # Human-readable JSON
     include_timestamps: true          # Include analysis timestamps
     output_directory: "./results"     # Output directory
     filename_template: "dexray_{apk_name}_{timestamp}.json"

**Template Variables**:

* ``{apk_name}`` - APK filename without extension
* ``{timestamp}`` - Analysis timestamp (YYYY-MM-DD_HH-MM-SS)
* ``{package_name}`` - Application package name (if available)
* ``{version}`` - Application version (if available)

Error Handling in Output
------------------------

Failed Module Results
~~~~~~~~~~~~~~~~~~~~

When modules fail, their results include error information:

.. code-block:: json

   {
       "module_name": "signature_detection",
       "status": "FAILURE",
       "execution_time": 2.3,
       "error_message": "API key not configured",
       "error_details": {
           "error_type": "ConfigurationError",
           "provider": "virustotal",
           "suggested_action": "Configure API key in dexray.yaml"
       }
   }

Timeout Results
~~~~~~~~~~~~~~

Modules that exceed timeout limits:

.. code-block:: json

   {
       "module_name": "library_detection",
       "status": "TIMEOUT", 
       "execution_time": 300.0,
       "error_message": "Module execution timed out after 300 seconds",
       "partial_results": {
           "libraries_detected_before_timeout": 3,
           "analysis_completed_percentage": 65
       }
   }

Skipped Module Results
~~~~~~~~~~~~~~~~~~~~~

Modules that were skipped due to missing dependencies or configuration:

.. code-block:: json

   {
       "module_name": "native_analysis",
       "status": "SKIPPED",
       "execution_time": 0.0,
       "error_message": "radare2 not available",
       "skip_reason": "missing_dependency",
       "requirements_not_met": ["radare2", "r2pipe"]
   }

Working with Output Data
-----------------------

Python Integration
~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from pathlib import Path
   
   # Load analysis results
   def load_analysis_results(result_file):
       with open(result_file) as f:
           return json.load(f)
   
   # Extract specific information
   results = load_analysis_results("dexray_MyApp_2024-01-15_10-30-45.json")
   
   # Get basic APK info
   package_name = results["apk_overview"]["package_name"]
   permissions = results["apk_overview"]["permissions"]
   
   # Get security findings
   if results.get("security_assessment"):
       risk_level = results["security_assessment"]["overall_risk_level"]
       secrets = results["security_assessment"]["hardcoded_secrets"]
   
   # Get string analysis
   if results.get("string_analysis"):
       urls = results["string_analysis"]["urls"]
       ip_addresses = results["string_analysis"]["ip_addresses"]

Shell Scripting
~~~~~~~~~~~~~~

.. code-block:: bash

   #!/bin/bash
   
   # Extract key information using jq
   RESULT_FILE="dexray_MyApp_2024-01-15_10-30-45.json"
   
   # Get package name
   PACKAGE=$(jq -r '.apk_overview.package_name' "$RESULT_FILE")
   
   # Count dangerous permissions
   DANGEROUS_PERMS=$(jq '[.permission_analysis.permissions_by_category.dangerous[]] | length' "$RESULT_FILE")
   
   # Check for hardcoded secrets
   SECRET_COUNT=$(jq '[.security_assessment.hardcoded_secrets[]?] | length' "$RESULT_FILE")
   
   echo "Package: $PACKAGE"
   echo "Dangerous Permissions: $DANGEROUS_PERMS"
   echo "Hardcoded Secrets: $SECRET_COUNT"

Database Integration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   import sqlite3
   from datetime import datetime
   
   def store_analysis_results(db_path, result_file):
       """Store analysis results in SQLite database"""
       with open(result_file) as f:
           results = json.load(f)
       
       conn = sqlite3.connect(db_path)
       cursor = conn.cursor()
       
       # Create table if not exists
       cursor.execute('''
           CREATE TABLE IF NOT EXISTS analysis_results (
               id INTEGER PRIMARY KEY,
               package_name TEXT,
               version_name TEXT,
               analysis_date TEXT,
               risk_level TEXT,
               vulnerability_count INTEGER,
               permissions_count INTEGER,
               libraries_count INTEGER,
               results_json TEXT
           )
       ''')
       
       # Insert results
       apk_overview = results.get('apk_overview', {})
       security = results.get('security_assessment', {})
       
       cursor.execute('''
           INSERT INTO analysis_results (
               package_name, version_name, analysis_date,
               risk_level, vulnerability_count, permissions_count,
               libraries_count, results_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ''', (
           apk_overview.get('package_name'),
           apk_overview.get('version_name'), 
           results['analysis_metadata']['analysis_timestamp'],
           security.get('overall_risk_level'),
           security.get('total_vulnerabilities', 0),
           len(apk_overview.get('permissions', [])),
           results.get('library_detection', {}).get('total_libraries_detected', 0),
           json.dumps(results)
       ))
       
       conn.commit()
       conn.close()

The JSON output format provides comprehensive, structured data that enables automated processing, integration with security tools, and detailed analysis reporting.