Analysis Modules API
====================

Dexray Insight provides a comprehensive set of analysis modules for examining different aspects of Android APK files. Each module implements the ``BaseAnalysisModule`` interface and focuses on specific analysis domains.

APK Overview Module
-------------------

.. autoclass:: dexray_insight.apk_overview.app.AppOverviewModule
   :members:
   :undoc-members:
   :show-inheritance:

Extracts basic APK metadata, permissions, components, and native libraries. This is typically the first module to run and provides foundational information used by other modules.

**Analysis Capabilities**:

* APK metadata (package name, version, size, signatures)
* Android permissions analysis
* Application components (activities, services, receivers, providers)
* Native library detection (.so files)
* Framework detection (Flutter, React Native, Xamarin, Cordova)

**Key Methods**:

* ``extract_apk_metadata()`` - Extract APK file information and signatures
* ``extract_permissions()`` - Analyze declared and used permissions
* ``extract_components()`` - Extract activities, services, and other components
* ``extract_native_libraries()`` - Detect and extract native .so files

**Usage Example**:

.. code-block:: python

   # Native library extraction with fallback
   native_libs = androguard_obj.get_libraries()
   has_so_files = any(lib.endswith('.so') for lib in native_libs)
   
   if not has_so_files and temporal_paths:
       # Fallback to directory parsing
       lib_dir = temporal_paths.unzipped_dir / 'lib'
       so_files = list(lib_dir.rglob('*.so'))
       native_libs = [f.name for f in so_files]

**Result Structure**:

.. code-block:: python

   {
       'package_name': 'com.example.app',
       'version_name': '1.0.0', 
       'version_code': 1,
       'permissions': ['android.permission.INTERNET'],
       'activities': ['MainActivity', 'SettingsActivity'],
       'native_libraries': ['libexample.so', 'libcrypto.so'],
       'framework': 'Native'  # or Flutter, React Native, etc.
   }

Permission Analysis Module
--------------------------

.. autoclass:: dexray_insight.modules.permission_analysis.PermissionAnalysisModule
   :members:
   :undoc-members:
   :show-inheritance:

Analyzes Android permissions for security implications and identifies critical or dangerous permissions.

**Analysis Capabilities**:

* Critical permission identification
* Permission categorization (normal, dangerous, signature)
* Custom permission analysis
* Permission combination risk assessment

**Configuration**:

.. code-block:: yaml

   modules:
     permission_analysis:
       enabled: true
       critical_permissions_file: null  # Custom critical permissions list
       use_default_critical_list: true

**Critical Permissions Detected**:

* Location permissions (ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION)
* Privacy permissions (READ_CONTACTS, READ_SMS, CAMERA)
* System permissions (WRITE_EXTERNAL_STORAGE, SYSTEM_ALERT_WINDOW)
* Network permissions (INTERNET, ACCESS_NETWORK_STATE)
* Device permissions (READ_PHONE_STATE, RECORD_AUDIO)

String Analysis Module
----------------------

.. autoclass:: dexray_insight.modules.string_analysis.StringAnalysisModule
   :members:
   :undoc-members:
   :show-inheritance:

Extracts and analyzes strings from APK files to identify URLs, IP addresses, email addresses, domains, and encoded content.

**Pattern Detection**:

* **IP Addresses**: IPv4 and IPv6 address patterns
* **URLs**: HTTP/HTTPS URLs with domain validation
* **Email Addresses**: RFC-compliant email pattern matching
* **Domains**: Domain name extraction and validation
* **Base64 Strings**: Encoded content detection with entropy analysis

**Configuration**:

.. code-block:: yaml

   modules:
     string_analysis:
       patterns:
         ip_addresses: true
         urls: true 
         email_addresses: true
         domains: true
         base64_strings: true
       filters:
         min_string_length: 2
         exclude_patterns: []

**Usage Example**:

.. code-block:: python

   # Access string analysis results in other modules
   if 'string_analysis' in context.module_results:
       string_data = context.module_results['string_analysis']
       urls = string_data.get('urls', [])
       ip_addresses = string_data.get('ip_addresses', [])

**Result Structure**:

.. code-block:: python

   {
       'urls': ['https://api.example.com', 'http://tracking.com'],
       'ip_addresses': ['192.168.1.1', '8.8.8.8'],
       'email_addresses': ['contact@example.com'],
       'domains': ['api.example.com', 'cdn.example.com'],
       'base64_strings': ['dGVzdCBzdHJpbmc='],
       'total_strings': 1247
   }

Signature Detection Module
--------------------------

.. autoclass:: dexray_insight.modules.signature_detection.SignatureDetectionModule
   :members:
   :undoc-members:
   :show-inheritance:

Integrates with threat intelligence APIs to check APK signatures against known malware databases.

**Supported Services**:

* **VirusTotal**: Comprehensive malware scanning with 70+ engines
* **Koodous**: Android-specific malware detection community
* **Triage**: Automated malware analysis sandbox

**Configuration**:

.. code-block:: yaml

   modules:
     signature_detection:
       enabled: true
       providers:
         virustotal:
           enabled: true
           api_key: "YOUR_API_KEY"
           rate_limit: 4  # requests per minute
         koodous:
           enabled: true
           api_key: "YOUR_API_KEY"
         triage:
           enabled: true
           api_key: "YOUR_API_KEY"

**Result Structure**:

.. code-block:: python

   {
       'virustotal': {
           'detection_ratio': '5/70',
           'positives': 5,
           'total': 70,
           'scan_date': '2024-01-15 10:30:00',
           'malware_families': ['Android.Trojan.Banker']
       },
       'koodous': {
           'detected': True,
           'rating': 7,
           'analysis_url': 'https://koodous.com/analysis/...'
       }
   }

Manifest Analysis Module
------------------------

.. autoclass:: dexray_insight.modules.manifest_analysis.ManifestAnalysisModule
   :members:
   :undoc-members:
   :show-inheritance:

Analyzes AndroidManifest.xml for security configurations, component definitions, and intent filters.

**Analysis Capabilities**:

* Intent filter analysis for security implications
* Exported component detection
* Custom permission definitions
* Application component relationships
* Security policy analysis (network security config, backup settings)

**Security Checks**:

* Exported components without proper protection
* Intent filters that may be exploitable
* Debug mode enabled in production
* Backup allowed settings
* Network security configuration

**Configuration**:

.. code-block:: yaml

   modules:
     manifest_analysis:
       enabled: true
       extract_intent_filters: true
       analyze_exported_components: true

**Result Structure**:

.. code-block:: python

   {
       'exported_activities': [
           {
               'name': 'MainActivity',
               'exported': True,
               'intent_filters': ['android.intent.action.MAIN']
           }
       ],
       'exported_services': [],
       'exported_receivers': [],
       'security_issues': [
           'Activity MainActivity is exported without permission protection'
       ]
   }

API Invocation Analysis Module
------------------------------

.. autoclass:: dexray_insight.modules.api_invocation.ApiInvocationModule
   :members:
   :undoc-members:
   :show-inheritance:

Analyzes method calls and reflection usage within the APK. This module has significant performance impact and is disabled by default.

**Analysis Capabilities**:

* Method call graph analysis
* Reflection usage detection
* Dynamic class loading detection
* Native method invocations
* Crypto API usage patterns

**Configuration**:

.. code-block:: yaml

   modules:
     api_invocation:
       enabled: false  # Disabled by default
       reflection_analysis: true

**Performance Considerations**:

This module performs deep code analysis and can significantly increase analysis time. Enable only when detailed API analysis is required.

Tracker Analysis Module
-----------------------

.. autoclass:: dexray_insight.modules.tracker_analysis.TrackerAnalysisModule
   :members:
   :undoc-members:
   :show-inheritance:

Identifies third-party tracking libraries using the Exodus Privacy database.

**Detection Capabilities**:

* Advertising trackers (Google AdMob, Facebook Audience Network)
* Analytics trackers (Google Analytics, Firebase Analytics)
* Crash reporting (Crashlytics, Bugsnag)
* Social media SDKs (Facebook SDK, Twitter SDK)
* Location tracking libraries

**Configuration**:

.. code-block:: yaml

   modules:
     tracker_analysis:
       enabled: true
       fetch_exodus_trackers: true
       exodus_api_url: "https://reports.exodus-privacy.eu.org/api/trackers"
       api_timeout: 10

**Result Structure**:

.. code-block:: python

   {
       'trackers_found': [
           {
               'name': 'Google AdMob',
               'category': 'Advertisement',
               'website': 'https://admob.google.com',
               'detection_method': 'exodus_signature'
           }
       ],
       'tracker_count': 3,
       'categories': ['Advertisement', 'Analytics']
   }

Library Detection Module
------------------------

.. autoclass:: dexray_insight.modules.library_detection.LibraryDetectionModule
   :members:
   :undoc-members:
   :show-inheritance:

Identifies third-party libraries using heuristic and similarity analysis techniques.

**Detection Methods**:

* **Stage 1 - Heuristic Detection**: Pattern-based identification using package names, class names, and manifest elements
* **Stage 2 - Similarity Analysis**: LibScan-inspired structural comparison

**Configuration**:

.. code-block:: yaml

   modules:
     library_detection:
       enable_heuristic: true
       confidence_threshold: 0.7
       enable_similarity: true
       similarity_threshold: 0.85
       custom_patterns: {}  # Custom library definitions

**Library Categories**:

* UI/UX libraries (Material Design, Support Libraries)
* Networking libraries (OkHttp, Retrofit, Volley)
* Image processing (Glide, Picasso, Fresco)
* Database libraries (Room, SQLite, Realm)
* Utility libraries (Apache Commons, Guava)

**Result Structure**:

.. code-block:: python

   {
       'libraries_detected': [
           {
               'name': 'OkHttp',
               'category': 'networking',
               'version': '4.9.0',
               'confidence': 0.95,
               'detection_method': 'heuristic_package_analysis'
           }
       ],
       'total_libraries': 12,
       'categories_found': ['networking', 'ui', 'utility']
   }

Behavior Analysis Module
------------------------

.. autoclass:: dexray_insight.modules.behaviour_analysis.BehaviourAnalysisModule
   :members:
   :undoc-members:
   :show-inheritance:

Analyzes privacy-sensitive behaviors and advanced techniques used by the application.

**Behavioral Patterns Detected**:

* **Device Information Access**: Model, IMEI, Android version
* **Privacy-Sensitive Data**: Clipboard, phone number, contacts
* **System Interaction**: Dynamic receivers, running services
* **Advanced Techniques**: Reflection usage, native code integration

**Configuration**:

.. code-block:: yaml

   modules:
     behaviour_analysis:
       enabled: true
       deep_mode: false  # Enable with --deep flag
       features:
         device_model_access: true
         imei_access: true
         clipboard_usage: true
         reflection_usage: true

**Deep Mode Features**:

When enabled with ``--deep`` flag, performs more comprehensive analysis:

* Advanced reflection pattern detection
* Complex obfuscation technique identification
* Detailed privacy behavior analysis
* Advanced evasion technique detection

Native Analysis Module
----------------------

.. autoclass:: dexray_insight.modules.native.native_loader.NativeAnalysisLoader
   :members:
   :undoc-members:
   :show-inheritance:

Orchestrates analysis of native binaries (.so files) using Radare2 integration.

**Prerequisites**:

* Temporal analysis must be enabled (APK extracted)
* Radare2 and r2pipe must be installed
* Native binaries must be present in APK

**Architecture Support**:

.. code-block:: yaml

   modules:
     native_analysis:
       architectures:
         - "arm64-v8a"      # Primary target
         - "armeabi-v7a"    # Optional
         - "x86_64"         # Optional

**Native String Extraction**:

.. autoclass:: dexray_insight.modules.native.string_extraction.NativeStringExtractionModule
   :members:
   :undoc-members:
   :show-inheritance:

Extracts strings from native binaries using Radare2's string analysis capabilities.

**String Sources**:

* Data section strings (high confidence)
* All section strings (medium confidence)
* Text parsing fallback (lower confidence)

**Configuration**:

.. code-block:: yaml

   modules:
     native_analysis:
       modules:
         string_extraction:
           enabled: true
           min_string_length: 4
           max_string_length: 1024
           encoding: "utf-8"
           fallback_encodings: ["latin1", "ascii"]

**Result Structure**:

.. code-block:: python

   {
       'analyzed_binaries': [
           {
               'file_path': 'lib/arm64-v8a/libexample.so',
               'architecture': 'arm64-v8a',
               'file_size': 245760
           }
       ],
       'total_strings_extracted': 127,
       'strings_by_source': {
           'lib/arm64-v8a/libexample.so': [
               {
                   'content': 'https://api.example.com',
                   'extraction_method': 'r2_iz_data_sections',
                   'confidence': 0.9
               }
           ]
       }
   }

Module Development
------------------

Creating Custom Modules
~~~~~~~~~~~~~~~~~~~~~~~~

To create a custom analysis module:

1. **Inherit from BaseAnalysisModule**:

.. code-block:: python

   from dexray_insight.core.base_classes import BaseAnalysisModule, register_module
   
   @register_module('my_custom_module')
   class MyCustomModule(BaseAnalysisModule):
       pass

2. **Implement Required Methods**:

.. code-block:: python

   def analyze(self, apk_path: str, context: AnalysisContext) -> BaseResult:
       # Your analysis implementation
       pass
   
   def get_dependencies(self) -> List[str]:
       return ['string_analysis']  # Dependencies on other modules

3. **Create Result Class**:

.. code-block:: python

   from dataclasses import dataclass
   from dexray_insight.core.base_classes import BaseResult
   
   @dataclass
   class MyCustomResult(BaseResult):
       custom_data: Dict[str, Any] = None

4. **Register Module**:

The ``@register_module`` decorator automatically registers the module with the framework.

Module Integration Patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Accessing Previous Results**:

.. code-block:: python

   def analyze(self, apk_path: str, context: AnalysisContext):
       # Access string analysis results
       if 'string_analysis' in context.module_results:
           strings = context.module_results['string_analysis']
           urls = strings.get('urls', [])

**Sharing Data Between Modules**:

.. code-block:: python

   # Store data for other modules
   context.shared_data['my_analysis'] = {
       'patterns': detected_patterns,
       'confidence': analysis_confidence
   }

**Using Temporal Analysis**:

.. code-block:: python

   # Access extracted APK files
   if context.temporal_paths:
       unzipped_dir = context.temporal_paths.unzipped_dir
       native_files = list(unzipped_dir.rglob('*.so'))

**Error Handling Best Practices**:

.. code-block:: python

   def analyze(self, apk_path: str, context: AnalysisContext):
       start_time = time.time()
       
       try:
           # Analysis implementation
           result = self._perform_analysis(apk_path, context)
           
           return MyCustomResult(
               module_name=self.get_module_name(),
               status=AnalysisStatus.SUCCESS,
               execution_time=time.time() - start_time,
               custom_data=result
           )
           
       except Exception as e:
           self.logger.error(f"Analysis failed: {e}")
           return MyCustomResult(
               module_name=self.get_module_name(),
               status=AnalysisStatus.FAILURE,
               execution_time=time.time() - start_time,
               error_message=str(e)
           )

Performance Optimization
~~~~~~~~~~~~~~~~~~~~~~~

**Module Priorities**:

Set appropriate priority values to control execution order:

.. code-block:: yaml

   modules:
     my_module:
       priority: 50  # Lower numbers run first

**Dependency Management**:

Specify only essential dependencies to avoid unnecessary waiting:

.. code-block:: python

   def get_dependencies(self) -> List[str]:
       # Only include modules whose results you actually need
       return ['apk_overview']  # Don't include optional dependencies

**Resource Usage**:

Consider memory and CPU usage for large APKs:

.. code-block:: python

   def analyze(self, apk_path: str, context: AnalysisContext):
       # Check APK size and adjust analysis depth
       apk_size = Path(apk_path).stat().st_size
       if apk_size > 100 * 1024 * 1024:  # 100MB
           self.logger.info("Large APK detected, using fast analysis mode")
           return self._fast_analysis(apk_path, context)
       else:
           return self._comprehensive_analysis(apk_path, context)