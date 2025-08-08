Results API
===========

Dexray Insight provides a comprehensive results framework that standardizes how analysis results are structured, accessed, and serialized. All analysis results inherit from base classes that provide consistent interfaces for result handling.

Full Analysis Results
---------------------

.. autoclass:: dexray_insight.results.full_analysis_results.FullAnalysisResults
   :members:
   :undoc-members:
   :show-inheritance:

The main container for all analysis results. This class aggregates results from all executed modules and provides unified access methods.

**Key Attributes**:

* ``apk_overview`` - Basic APK metadata and component information
* ``permission_analysis`` - Permission analysis results
* ``string_analysis`` - Extracted strings and patterns
* ``signature_detection`` - Threat intelligence results
* ``manifest_analysis`` - AndroidManifest.xml analysis
* ``library_detection`` - Third-party library identification
* ``tracker_analysis`` - Tracking library detection
* ``behaviour_analysis`` - Privacy and behavioral analysis
* ``native_analysis`` - Native binary analysis results
* ``security_assessment`` - OWASP Top 10 security assessment

**Key Methods**:

* ``to_dict()`` - Convert all results to dictionary for JSON serialization
* ``to_json(indent=2)`` - Convert to formatted JSON string
* ``print_results()`` - Print formatted results to console
* ``print_analyst_summary()`` - Print analyst-friendly summary
* ``get_security_results_dict()`` - Extract security-specific results

**Usage Examples**:

.. code-block:: python

   # Access specific module results
   results = engine.analyze_apk("app.apk", androguard_obj)
   
   # Get APK overview information
   package_name = results.apk_overview.package_name
   permissions = results.apk_overview.permissions
   
   # Get string analysis results
   if results.string_analysis:
       urls = results.string_analysis.urls
       ip_addresses = results.string_analysis.ip_addresses
   
   # Export to JSON
   json_data = results.to_json()
   with open("results.json", "w") as f:
       f.write(json_data)
   
   # Print analyst summary
   results.print_analyst_summary()

**Result Structure**:

.. code-block:: python

   {
       "analysis_metadata": {
           "timestamp": "2024-01-15T10:30:00Z",
           "dexray_version": "1.0.0",
           "analysis_duration": 45.3
       },
       "apk_overview": {
           "package_name": "com.example.app",
           "version_name": "1.0.0",
           "permissions": [...],
           "activities": [...],
           "native_libraries": [...]
       },
       "string_analysis": {
           "urls": [...],
           "ip_addresses": [...],
           "domains": [...]
       },
       "security_assessment": {
           "owasp_findings": [...],
           "risk_level": "HIGH"
       }
   }

Base Result Classes
-------------------

.. autoclass:: dexray_insight.core.base_classes.BaseResult
   :members:
   :undoc-members:
   :show-inheritance:

Abstract base class for all analysis results providing standardized structure and methods.

**Standard Fields**:

* ``module_name`` - Name of the analysis module that generated the result
* ``status`` - Execution status (SUCCESS, FAILURE, SKIPPED, TIMEOUT)  
* ``execution_time`` - Time taken for analysis in seconds
* ``error_message`` - Error details if analysis failed

**Key Methods**:

* ``to_dict()`` - Convert result to dictionary for serialization
* ``is_successful()`` - Check if analysis completed successfully
* ``__post_init__()`` - Initialize default values (override in subclasses)

**Usage in Custom Results**:

.. code-block:: python

   from dataclasses import dataclass
   from dexray_insight.core.base_classes import BaseResult, AnalysisStatus
   
   @dataclass
   class MyCustomResult(BaseResult):
       custom_data: Dict[str, Any] = None
       findings_count: int = 0
       
       def __post_init__(self):
           if self.custom_data is None:
               self.custom_data = {}
       
       def to_dict(self) -> Dict[str, Any]:
           base_dict = super().to_dict()
           base_dict.update({
               'custom_data': self.custom_data,
               'findings_count': self.findings_count
           })
           return base_dict

Module-Specific Results
----------------------

APK Overview Results
~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.results.apk_overview_results.ApkOverviewResult
   :members:
   :undoc-members:
   :show-inheritance:

Contains comprehensive APK metadata and component information.

**Key Fields**:

* ``package_name`` - Application package identifier
* ``version_name`` - Human-readable version string
* ``version_code`` - Internal version number
* ``min_sdk_version`` - Minimum Android SDK version
* ``target_sdk_version`` - Target Android SDK version
* ``permissions`` - List of declared permissions
* ``activities`` - List of activity components
* ``services`` - List of service components
* ``receivers`` - List of broadcast receiver components
* ``providers`` - List of content provider components
* ``native_libraries`` - List of native .so files
* ``framework`` - Detected framework (Native, Flutter, React Native, etc.)

**Example Access**:

.. code-block:: python

   apk_result = results.apk_overview
   
   print(f"Package: {apk_result.package_name}")
   print(f"Version: {apk_result.version_name} ({apk_result.version_code})")
   print(f"Framework: {apk_result.framework}")
   print(f"Native Libraries: {len(apk_result.native_libraries)}")
   
   # Check for specific permissions
   if 'android.permission.CAMERA' in apk_result.permissions:
       print("App requests camera permission")

String Analysis Results
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.results.string_analysis_results.StringAnalysisResult
   :members:
   :undoc-members:
   :show-inheritance:

Contains extracted strings categorized by pattern type.

**Key Fields**:

* ``urls`` - List of extracted URLs
* ``ip_addresses`` - List of IP addresses (IPv4 and IPv6)
* ``email_addresses`` - List of email addresses
* ``domains`` - List of domain names
* ``base64_strings`` - List of Base64 encoded strings
* ``total_strings`` - Total number of strings analyzed

**Pattern Analysis**:

.. code-block:: python

   string_result = results.string_analysis
   
   # Analyze network communications
   print(f"Found {len(string_result.urls)} URLs:")
   for url in string_result.urls[:5]:  # Show first 5
       print(f"  - {url}")
   
   # Check for suspicious domains
   suspicious_domains = ['bit.ly', 'tinyurl.com', 't.co']
   found_suspicious = [d for d in string_result.domains 
                      if any(sus in d for sus in suspicious_domains)]
   
   if found_suspicious:
       print(f"Suspicious domains found: {found_suspicious}")

Security Assessment Results
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.results.security_assessment_results.SecurityAssessmentResult  
   :members:
   :undoc-members:
   :show-inheritance:

Contains OWASP Top 10 security analysis results with detailed findings.

**Key Fields**:

* ``owasp_findings`` - List of OWASP Top 10 security issues
* ``hardcoded_secrets`` - List of detected secrets and keys
* ``risk_level`` - Overall risk assessment (LOW, MEDIUM, HIGH, CRITICAL)
* ``vulnerability_count`` - Total number of vulnerabilities found
* ``recommendations`` - List of security recommendations

**Secret Detection Results**:

.. code-block:: python

   security_result = results.security_assessment
   
   # Check overall security status
   print(f"Risk Level: {security_result.risk_level}")
   print(f"Vulnerabilities Found: {security_result.vulnerability_count}")
   
   # Analyze hardcoded secrets
   if security_result.hardcoded_secrets:
       print("🔑 HARDCODED SECRETS DETECTED:")
       for secret in security_result.hardcoded_secrets:
           print(f"  [{secret['severity']}] {secret['type']}: {secret['value'][:20]}...")
           print(f"      Location: {secret['location']}")
           print(f"      Context: {secret['context']}")
   
   # Review OWASP findings
   for finding in security_result.owasp_findings:
       print(f"[{finding['category']}] {finding['description']}")

Library Detection Results
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.results.library_detection_results.LibraryDetectionResult
   :members:
   :undoc-members:
   :show-inheritance:

Contains identified third-party libraries with confidence scores.

**Key Fields**:

* ``libraries_detected`` - List of detected libraries
* ``total_libraries`` - Total number of libraries found
* ``categories_found`` - List of library categories present
* ``detection_methods`` - Methods used for detection

**Library Analysis**:

.. code-block:: python

   library_result = results.library_detection
   
   print(f"Libraries Detected: {library_result.total_libraries}")
   print(f"Categories: {', '.join(library_result.categories_found)}")
   
   # Analyze high-confidence detections
   high_confidence = [lib for lib in library_result.libraries_detected 
                     if lib['confidence'] > 0.8]
   
   print(f"\nHigh-confidence library detections ({len(high_confidence)}):")
   for lib in high_confidence:
       print(f"  - {lib['name']} ({lib['category']}) - {lib['confidence']:.2f}")

Native Analysis Results
~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.modules.native.native_loader.NativeAnalysisModuleResult
   :members:
   :undoc-members:
   :show-inheritance:

Contains results from native binary analysis including string extraction.

**Key Fields**:

* ``analyzed_binaries`` - List of analyzed native binaries
* ``total_strings_extracted`` - Number of strings extracted from native code
* ``strings_by_source`` - Strings organized by source binary
* ``radare2_available`` - Whether Radare2 was available for analysis

**Native String Analysis**:

.. code-block:: python

   native_result = results.native_analysis
   
   if native_result and native_result.radare2_available:
       print(f"Native Binaries Analyzed: {len(native_result.analyzed_binaries)}")
       print(f"Strings Extracted: {native_result.total_strings_extracted}")
       
       # Analyze strings by architecture
       for binary_info in native_result.analyzed_binaries:
           arch = binary_info['architecture']
           binary_path = binary_info['relative_path']
           if binary_path in native_result.strings_by_source:
               strings = native_result.strings_by_source[binary_path]
               print(f"  {arch}: {len(strings)} strings")

Result Serialization
-------------------

JSON Export
~~~~~~~~~~~

All results can be exported to JSON format for storage and further analysis:

.. code-block:: python

   # Export complete results
   json_output = results.to_json(indent=2)
   
   # Save to file
   import json
   with open("analysis_results.json", "w") as f:
       json.dump(results.to_dict(), f, indent=2)
   
   # Export specific module results
   string_data = results.string_analysis.to_dict() if results.string_analysis else {}
   
   # Export security results only
   security_data = results.get_security_results_dict()

Dictionary Conversion
~~~~~~~~~~~~~~~~~~~~

Results can be converted to Python dictionaries for programmatic access:

.. code-block:: python

   # Convert all results to dictionary
   result_dict = results.to_dict()
   
   # Access nested data
   package_name = result_dict['apk_overview']['package_name']
   urls = result_dict.get('string_analysis', {}).get('urls', [])
   
   # Iterate through findings
   if 'security_assessment' in result_dict:
       for finding in result_dict['security_assessment']['owasp_findings']:
           print(f"Security Issue: {finding['description']}")

Custom Serialization
~~~~~~~~~~~~~~~~~~~~

For custom result classes, implement serialization methods:

.. code-block:: python

   @dataclass
   class MyCustomResult(BaseResult):
       custom_data: Dict[str, Any] = None
       
       def to_dict(self) -> Dict[str, Any]:
           base_dict = super().to_dict()
           base_dict.update({
               'custom_data': self.custom_data,
               'summary': self._generate_summary()
           })
           return base_dict
       
       def _generate_summary(self) -> str:
           if self.custom_data:
               return f"Found {len(self.custom_data)} items"
           return "No items found"

Result Analysis Patterns
------------------------

Risk Assessment
~~~~~~~~~~~~~~~

Combine results from multiple modules for comprehensive risk assessment:

.. code-block:: python

   def assess_app_risk(results: FullAnalysisResults) -> str:
       risk_factors = []
       
       # Check permissions
       if results.apk_overview:
           dangerous_perms = ['CAMERA', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION']
           has_dangerous = any(perm for perm in results.apk_overview.permissions 
                             if any(d in perm for d in dangerous_perms))
           if has_dangerous:
               risk_factors.append("Requests sensitive permissions")
       
       # Check security assessment
       if results.security_assessment:
           if results.security_assessment.risk_level in ['HIGH', 'CRITICAL']:
               risk_factors.append("Security vulnerabilities detected")
       
       # Check trackers
       if results.tracker_analysis:
           if results.tracker_analysis.tracker_count > 5:
               risk_factors.append("Excessive tracking libraries")
       
       # Determine overall risk
       if len(risk_factors) >= 3:
           return "HIGH_RISK"
       elif len(risk_factors) >= 1:
           return "MEDIUM_RISK"
       else:
           return "LOW_RISK"

Data Correlation
~~~~~~~~~~~~~~~

Correlate findings across different analysis modules:

.. code-block:: python

   def correlate_network_activity(results: FullAnalysisResults) -> Dict[str, Any]:
       network_indicators = {
           'urls': [],
           'domains': [],
           'ip_addresses': [],
           'permissions': []
       }
       
       # Collect from string analysis
       if results.string_analysis:
           network_indicators['urls'] = results.string_analysis.urls
           network_indicators['domains'] = results.string_analysis.domains
           network_indicators['ip_addresses'] = results.string_analysis.ip_addresses
       
       # Add native analysis strings
       if results.native_analysis:
           for strings in results.native_analysis.strings_by_source.values():
               for string_obj in strings:
                   content = string_obj['content']
                   if content.startswith('http'):
                       network_indicators['urls'].append(content)
       
       # Check network permissions
       if results.apk_overview:
           network_perms = ['INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE']
           has_network_perms = [p for p in results.apk_overview.permissions
                               if any(np in p for np in network_perms)]
           network_indicators['permissions'] = has_network_perms
       
       return network_indicators

Reporting and Visualization
---------------------------

Analyst Summary Generation
~~~~~~~~~~~~~~~~~~~~~~~~~

Generate human-readable summaries from analysis results:

.. code-block:: python

   def generate_analyst_report(results: FullAnalysisResults) -> str:
       report_lines = []
       
       # Executive Summary
       if results.apk_overview:
           report_lines.append(f"📱 APK Analysis Report")
           report_lines.append(f"Package: {results.apk_overview.package_name}")
           report_lines.append(f"Version: {results.apk_overview.version_name}")
           report_lines.append("")
       
       # Security Assessment
       if results.security_assessment:
           risk = results.security_assessment.risk_level
           vuln_count = results.security_assessment.vulnerability_count
           report_lines.append(f"🛡️ Security Assessment: {risk} RISK")
           report_lines.append(f"   Vulnerabilities Found: {vuln_count}")
           
           if results.security_assessment.hardcoded_secrets:
               secret_count = len(results.security_assessment.hardcoded_secrets)
               report_lines.append(f"   🔑 Hardcoded Secrets: {secret_count}")
       
       # Privacy Analysis
       if results.tracker_analysis:
           tracker_count = results.tracker_analysis.tracker_count
           if tracker_count > 0:
               report_lines.append(f"📊 Privacy: {tracker_count} tracking libraries detected")
       
       return "\n".join(report_lines)

Data Export for External Tools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Export results in formats suitable for external analysis tools:

.. code-block:: python

   def export_for_splunk(results: FullAnalysisResults) -> Dict[str, Any]:
       """Export results in Splunk-friendly format"""
       return {
           'timestamp': results.analysis_metadata.get('timestamp'),
           'event_type': 'apk_analysis',
           'package_name': results.apk_overview.package_name if results.apk_overview else None,
           'risk_level': results.security_assessment.risk_level if results.security_assessment else 'UNKNOWN',
           'vulnerability_count': results.security_assessment.vulnerability_count if results.security_assessment else 0,
           'tracker_count': results.tracker_analysis.tracker_count if results.tracker_analysis else 0,
           'native_libraries_count': len(results.apk_overview.native_libraries) if results.apk_overview else 0
       }
   
   def export_ioc_indicators(results: FullAnalysisResults) -> List[Dict[str, Any]]:
       """Export Indicators of Compromise (IOCs)"""
       iocs = []
       
       if results.string_analysis:
           # Export URLs as IOCs
           for url in results.string_analysis.urls:
               iocs.append({
                   'type': 'url',
                   'value': url,
                   'source': 'string_analysis',
                   'confidence': 'medium'
               })
           
           # Export IP addresses as IOCs
           for ip in results.string_analysis.ip_addresses:
               iocs.append({
                   'type': 'ip',
                   'value': ip,
                   'source': 'string_analysis',
                   'confidence': 'medium'
               })
       
       return iocs

Error Handling in Results
-------------------------

Result Validation
~~~~~~~~~~~~~~~~

Validate results before processing:

.. code-block:: python

   def validate_results(results: FullAnalysisResults) -> List[str]:
       validation_errors = []
       
       # Check if critical modules completed successfully
       if not results.apk_overview:
           validation_errors.append("APK overview analysis missing")
       elif results.apk_overview.status != AnalysisStatus.SUCCESS:
           validation_errors.append("APK overview analysis failed")
       
       # Validate string analysis if enabled
       if results.string_analysis and results.string_analysis.status == AnalysisStatus.FAILURE:
           validation_errors.append("String analysis failed")
       
       return validation_errors

Graceful Degradation
~~~~~~~~~~~~~~~~~~~

Handle missing or failed module results gracefully:

.. code-block:: python

   def get_safe_package_name(results: FullAnalysisResults) -> str:
       """Get package name with fallback"""
       if results.apk_overview and results.apk_overview.package_name:
           return results.apk_overview.package_name
       return "unknown_package"
   
   def get_safe_url_count(results: FullAnalysisResults) -> int:
       """Get URL count with fallback"""
       if (results.string_analysis and 
           results.string_analysis.status == AnalysisStatus.SUCCESS and
           results.string_analysis.urls):
           return len(results.string_analysis.urls)
       return 0

Performance Considerations
~~~~~~~~~~~~~~~~~~~~~~~~~

When working with large result sets:

.. code-block:: python

   # Lazy loading of large result fields
   def get_string_summary(results: FullAnalysisResults) -> Dict[str, int]:
       """Get string counts without loading full string lists"""
       summary = {
           'urls': 0,
           'ip_addresses': 0,
           'domains': 0
       }
       
       if results.string_analysis and results.string_analysis.status == AnalysisStatus.SUCCESS:
           summary['urls'] = len(results.string_analysis.urls) if results.string_analysis.urls else 0
           summary['ip_addresses'] = len(results.string_analysis.ip_addresses) if results.string_analysis.ip_addresses else 0
           summary['domains'] = len(results.string_analysis.domains) if results.string_analysis.domains else 0
       
       return summary
   
   # Memory-efficient result processing
   def process_results_streaming(results: FullAnalysisResults):
       """Process results without loading everything into memory"""
       # Process each module result separately
       if results.string_analysis:
           yield ('string_analysis', results.string_analysis.to_dict())
       
       if results.security_assessment:
           yield ('security_assessment', results.security_assessment.to_dict())
       
       # Continue for other modules...