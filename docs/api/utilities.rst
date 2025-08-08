Utilities API
=============

Dexray Insight provides a comprehensive set of utility functions and classes that support the core analysis framework. These utilities handle common tasks such as file operations, logging, JSON serialization, and Android-specific operations.

File Utilities
--------------

.. automodule:: dexray_insight.Utils.file_utils
   :members:
   :undoc-members:

The file utilities module provides functions for handling file paths, JSON operations, and file system interactions.

Core Functions
~~~~~~~~~~~~~~

.. autofunction:: dexray_insight.Utils.file_utils.split_path_file_extension

Splits a file path into directory, filename, and extension components.

**Parameters**:
  * ``file_path`` (str): Full path to the file

**Returns**:
  * ``tuple[str, str, str]``: (directory, filename_without_extension, extension)

**Usage Example**:

.. code-block:: python

   from dexray_insight.Utils.file_utils import split_path_file_extension
   
   # Basic usage
   base_dir, name, ext = split_path_file_extension("/path/to/app.apk")
   print(f"Directory: {base_dir}")  # /path/to
   print(f"Name: {name}")           # app
   print(f"Extension: {ext}")       # apk
   
   # Handle complex filenames
   base_dir, name, ext = split_path_file_extension("/path/to/com.example.app-v1.2.3.apk")
   print(f"Name: {name}")           # com.example.app-v1.2.3
   print(f"Extension: {ext}")       # apk

**Cross-Platform Considerations**:

The function handles different path separators and behaves consistently across Windows and Unix-like systems:

.. code-block:: python

   # Unix path
   split_path_file_extension("/home/user/app.apk")
   # Returns: ('/home/user', 'app', 'apk')
   
   # Windows path (on Windows)
   split_path_file_extension("C:\\Users\\user\\app.apk")
   # Returns: ('C:\\Users\\user', 'app', 'apk')
   
   # Relative paths
   split_path_file_extension("./app.apk")
   # Returns: ('.', 'app', 'apk')

.. autofunction:: dexray_insight.Utils.file_utils.dump_json

Serializes Python objects to JSON format and saves to file.

**Parameters**:
  * ``filename`` (str): Output filename
  * ``data`` (Any): Python object to serialize
  * ``indent`` (int, optional): JSON indentation level (default: 2)

**Usage Example**:

.. code-block:: python

   from dexray_insight.Utils.file_utils import dump_json
   
   # Save analysis results
   analysis_data = {
       'package_name': 'com.example.app',
       'permissions': ['android.permission.INTERNET'],
       'urls': ['https://api.example.com']
   }
   
   dump_json('analysis_results.json', analysis_data)
   
   # Custom indentation
   dump_json('compact_results.json', analysis_data, indent=0)

**Error Handling**:

The function handles common serialization errors and provides meaningful error messages:

.. code-block:: python

   # Handle non-serializable objects
   try:
       dump_json('results.json', {'timestamp': datetime.now()})
   except TypeError as e:
       print(f"Serialization error: {e}")
       # Convert to serializable format
       data['timestamp'] = str(datetime.now())
       dump_json('results.json', data)

Androguard Integration
----------------------

.. automodule:: dexray_insight.Utils.androguardObjClass
   :members:
   :undoc-members:

Provides wrapper classes and utilities for integrating with the Androguard Android analysis library.

Androguard Object Wrapper
~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.Utils.androguardObjClass.Androguard_Obj
   :members:
   :undoc-members:
   :show-inheritance:

Main wrapper class for Androguard APK analysis objects, providing a simplified interface to Androguard's functionality.

**Key Methods**:

* ``__init__(apk_path)`` - Initialize Androguard analysis for APK file
* ``get_package()`` - Get application package name
* ``get_android_version()`` - Get target Android version
* ``get_permissions()`` - Get declared permissions list
* ``get_activities()`` - Get application activities
* ``get_services()`` - Get application services
* ``get_receivers()`` - Get broadcast receivers
* ``get_providers()`` - Get content providers
* ``get_libraries()`` - Get native libraries
* ``is_valid_apk()`` - Check if APK is valid and parseable

**Usage Example**:

.. code-block:: python

   from dexray_insight.Utils.androguardObjClass import Androguard_Obj
   
   # Initialize analysis
   androguard_obj = Androguard_Obj("path/to/app.apk")
   
   if androguard_obj.is_valid_apk():
       # Extract basic information
       package_name = androguard_obj.get_package()
       permissions = androguard_obj.get_permissions()
       activities = androguard_obj.get_activities()
       
       print(f"Package: {package_name}")
       print(f"Permissions: {len(permissions)}")
       print(f"Activities: {len(activities)}")
       
       # Get native libraries
       libraries = androguard_obj.get_libraries()
       native_libs = [lib for lib in libraries if lib.endswith('.so')]
       print(f"Native libraries: {len(native_libs)}")
   else:
       print("Invalid or corrupted APK file")

**Error Handling**:

.. code-block:: python

   try:
       androguard_obj = Androguard_Obj("corrupted.apk")
       if not androguard_obj.is_valid_apk():
           raise ValueError("Invalid APK file")
   except Exception as e:
       print(f"Failed to analyze APK: {e}")

**Performance Considerations**:

The Androguard_Obj class performs full APK parsing during initialization. For large APKs, consider:

.. code-block:: python

   import time
   
   start_time = time.time()
   androguard_obj = Androguard_Obj("large_app.apk")
   load_time = time.time() - start_time
   
   print(f"APK loading took {load_time:.2f} seconds")
   
   # Cache the object for multiple analyses
   cached_objects = {}
   apk_path = "app.apk"
   if apk_path not in cached_objects:
       cached_objects[apk_path] = Androguard_Obj(apk_path)

Logging Utilities
-----------------

.. automodule:: dexray_insight.Utils.log
   :members:
   :undoc-members:

Provides logging configuration and utilities for the Dexray Insight framework.

Logger Configuration
~~~~~~~~~~~~~~~~~~~

.. autofunction:: dexray_insight.Utils.log.set_logger

Configures the logging system based on command-line arguments and configuration settings.

**Parameters**:
  * ``args``: Parsed command-line arguments containing logging configuration

**Usage Example**:

.. code-block:: python

   from dexray_insight.Utils.log import set_logger
   import argparse
   
   # Configure logging from command-line args
   parser = argparse.ArgumentParser()
   parser.add_argument('-d', '--debug', default='ERROR')
   parser.add_argument('-f', '--filter', nargs='+')
   args = parser.parse_args()
   
   # Set up logging
   set_logger(args)
   
   # Use logging in modules
   import logging
   logger = logging.getLogger(__name__)
   logger.info("Analysis started")
   logger.debug("Detailed debug information")

**Logging Levels**:

The logging system supports multiple levels:

* ``DEBUG`` - Detailed diagnostic information
* ``INFO`` - General information about analysis progress
* ``WARNING`` - Warning messages for non-critical issues
* ``ERROR`` - Error messages for failures

**Log Filtering**:

Filter logs by specific source files:

.. code-block:: bash

   # Filter logs from specific modules
   dexray-insight app.apk -d DEBUG -f string_analysis.py permission_analysis.py

**Custom Logger Setup**:

.. code-block:: python

   import logging
   
   # Create module-specific logger
   logger = logging.getLogger('my_custom_module')
   logger.setLevel(logging.INFO)
   
   # Add custom formatter
   formatter = logging.Formatter(
       '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
   )
   
   # Log analysis progress
   logger.info("Starting custom analysis")
   logger.debug("Processing APK components")
   logger.warning("Non-critical issue detected")
   logger.error("Analysis failed")

String Processing Utilities
---------------------------

Pattern Matching and Extraction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dexray Insight includes several utility functions for string pattern matching and extraction:

**URL Extraction**:

.. code-block:: python

   import re
   
   def extract_urls(text: str) -> List[str]:
       """Extract URLs from text using regex patterns"""
       url_pattern = r'https?://(?:[-\w.])+(?:\.[a-zA-Z]{2,})+(?:/[^?\s]*)?(?:\?[^#\s]*)?(?:#[^\s]*)?'
       return re.findall(url_pattern, text)
   
   # Usage
   text = "Visit https://example.com and http://api.test.com/v1"
   urls = extract_urls(text)
   print(urls)  # ['https://example.com', 'http://api.test.com/v1']

**IP Address Extraction**:

.. code-block:: python

   def extract_ip_addresses(text: str) -> List[str]:
       """Extract IPv4 and IPv6 addresses from text"""
       ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
       ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
       
       ipv4_matches = re.findall(ipv4_pattern, text)
       ipv6_matches = re.findall(ipv6_pattern, text)
       
       return ipv4_matches + ipv6_matches
   
   # Usage
   text = "Connect to 192.168.1.1 or 2001:db8::1"
   ips = extract_ip_addresses(text)
   print(ips)  # ['192.168.1.1', '2001:db8::1']

**Email Extraction**:

.. code-block:: python

   def extract_emails(text: str) -> List[str]:
       """Extract email addresses from text"""
       email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
       return re.findall(email_pattern, text)
   
   # Usage
   text = "Contact support@example.com or admin@test.org"
   emails = extract_emails(text)
   print(emails)  # ['support@example.com', 'admin@test.org']

**Base64 Detection**:

.. code-block:: python

   import base64
   
   def is_base64(s: str) -> bool:
       """Check if string is valid Base64"""
       try:
           if isinstance(s, str):
               s = s.encode('ascii')
           return base64.b64encode(base64.b64decode(s)) == s
       except Exception:
           return False
   
   def extract_base64_strings(text: str, min_length: int = 16) -> List[str]:
       """Extract potential Base64 encoded strings"""
       base64_pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
       potential_b64 = re.findall(base64_pattern, text)
       
       valid_b64 = []
       for candidate in potential_b64:
           if len(candidate) >= min_length and is_base64(candidate):
               valid_b64.append(candidate)
       
       return valid_b64

Entropy Analysis
~~~~~~~~~~~~~~~

Utility functions for analyzing string entropy to detect potential encoded content:

.. code-block:: python

   import math
   from collections import Counter
   
   def calculate_entropy(data: str) -> float:
       """Calculate Shannon entropy of string"""
       if not data:
           return 0
       
       # Count character frequencies
       counter = Counter(data)
       length = len(data)
       
       # Calculate entropy
       entropy = 0
       for count in counter.values():
           probability = count / length
           if probability > 0:
               entropy -= probability * math.log2(probability)
       
       return entropy
   
   def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
       """Check if string has high entropy (potentially encoded)"""
       return calculate_entropy(data) > threshold
   
   # Usage
   normal_text = "This is normal text"
   encoded_text = "dGhpcyBpcyBlbmNvZGVkIHRleHQ="
   
   print(f"Normal text entropy: {calculate_entropy(normal_text):.2f}")    # ~4.1
   print(f"Encoded text entropy: {calculate_entropy(encoded_text):.2f}")  # ~5.9
   
   print(f"High entropy: {is_high_entropy(encoded_text)}")  # True

Android Utilities
-----------------

Android-specific utility functions for handling APK components and data structures.

Permission Utilities
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   def is_dangerous_permission(permission: str) -> bool:
       """Check if permission is considered dangerous"""
       dangerous_perms = [
           'android.permission.CAMERA',
           'android.permission.READ_CONTACTS',
           'android.permission.WRITE_CONTACTS',
           'android.permission.ACCESS_FINE_LOCATION',
           'android.permission.ACCESS_COARSE_LOCATION',
           'android.permission.RECORD_AUDIO',
           'android.permission.READ_PHONE_STATE',
           'android.permission.CALL_PHONE',
           'android.permission.READ_SMS',
           'android.permission.SEND_SMS',
           'android.permission.WRITE_EXTERNAL_STORAGE'
       ]
       return permission in dangerous_perms
   
   def categorize_permissions(permissions: List[str]) -> Dict[str, List[str]]:
       """Categorize permissions by type"""
       categories = {
           'dangerous': [],
           'normal': [],
           'custom': [],
           'system': []
       }
       
       for perm in permissions:
           if is_dangerous_permission(perm):
               categories['dangerous'].append(perm)
           elif perm.startswith('android.permission.'):
               categories['normal'].append(perm)
           elif perm.startswith('android.'):
               categories['system'].append(perm)
           else:
               categories['custom'].append(perm)
       
       return categories

Framework Detection
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   def detect_framework(package_name: str, native_libraries: List[str], 
                       classes: List[str]) -> str:
       """Detect application framework based on indicators"""
       
       # Flutter detection
       flutter_indicators = ['libflutter.so', 'libapp.so']
       if any(lib in native_libraries for lib in flutter_indicators):
           return 'Flutter'
       
       # React Native detection
       rn_indicators = ['libreactnativejni.so', 'libhermes.so']
       if any(lib in native_libraries for lib in rn_indicators):
           return 'React Native'
       
       # Xamarin detection
       xamarin_indicators = ['libmonodroid.so', 'libmonosgen-2.0.so']
       if any(lib in native_libraries for lib in xamarin_indicators):
           return 'Xamarin'
       
       # Cordova/PhoneGap detection
       cordova_classes = ['org.apache.cordova', 'org.apache.phonegap']
       if any(cls_prefix in str(classes) for cls_prefix in cordova_classes):
           return 'Cordova'
       
       # Unity detection
       unity_indicators = ['libunity.so', 'libil2cpp.so']
       if any(lib in native_libraries for lib in unity_indicators):
           return 'Unity'
       
       return 'Native'

Component Analysis
~~~~~~~~~~~~~~~~~

.. code-block:: python

   def analyze_component_security(components: List[Dict]) -> List[Dict]:
       """Analyze Android components for security issues"""
       issues = []
       
       for component in components:
           component_name = component.get('name', 'unknown')
           is_exported = component.get('exported', False)
           permission = component.get('permission')
           intent_filters = component.get('intent_filters', [])
           
           # Check for exported components without permission protection
           if is_exported and not permission and intent_filters:
               issues.append({
                   'type': 'exported_without_permission',
                   'component': component_name,
                   'description': f'Component {component_name} is exported without permission protection',
                   'severity': 'MEDIUM'
               })
           
           # Check for dangerous intent filters
           dangerous_actions = [
               'android.intent.action.BOOT_COMPLETED',
               'android.intent.action.PACKAGE_REPLACED',
               'android.net.conn.CONNECTIVITY_CHANGE'
           ]
           
           for intent_filter in intent_filters:
               if any(action in intent_filter for action in dangerous_actions):
                   issues.append({
                       'type': 'dangerous_intent_filter',
                       'component': component_name,
                       'description': f'Component {component_name} uses sensitive intent filter',
                       'severity': 'HIGH'
                   })
       
       return issues

Data Validation Utilities
-------------------------

Input Validation
~~~~~~~~~~~~~~~

.. code-block:: python

   def validate_apk_path(apk_path: str) -> bool:
       """Validate APK file path"""
       from pathlib import Path
       
       path = Path(apk_path)
       
       # Check if file exists
       if not path.exists():
           return False
       
       # Check if it's a file (not directory)
       if not path.is_file():
           return False
       
       # Check file extension
       if path.suffix.lower() != '.apk':
           return False
       
       # Check file size (not empty)
       if path.stat().st_size == 0:
           return False
       
       return True
   
   def validate_configuration(config_dict: Dict[str, Any]) -> List[str]:
       """Validate configuration dictionary"""
       errors = []
       
       # Check required sections
       required_sections = ['analysis', 'modules', 'tools']
       for section in required_sections:
           if section not in config_dict:
               errors.append(f"Missing required section: {section}")
       
       # Validate analysis configuration
       if 'analysis' in config_dict:
           analysis = config_dict['analysis']
           if 'timeout' in analysis:
               timeout = analysis['timeout']
               if not isinstance(timeout.get('module_timeout'), int) or timeout.get('module_timeout') <= 0:
                   errors.append("Invalid module_timeout: must be positive integer")
       
       return errors

Data Sanitization
~~~~~~~~~~~~~~~~~

.. code-block:: python

   def sanitize_filename(filename: str) -> str:
       """Sanitize filename for safe file system usage"""
       import re
       
       # Remove or replace invalid characters
       sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
       
       # Remove leading/trailing whitespace and dots
       sanitized = sanitized.strip(' .')
       
       # Limit length
       if len(sanitized) > 255:
           sanitized = sanitized[:255]
       
       # Ensure not empty
       if not sanitized:
           sanitized = 'unnamed'
       
       return sanitized
   
   def sanitize_url(url: str) -> str:
       """Sanitize URL for safe processing"""
       import urllib.parse
       
       try:
           # Parse and reconstruct URL
           parsed = urllib.parse.urlparse(url)
           
           # Validate scheme
           if parsed.scheme not in ['http', 'https', 'ftp']:
               return None
           
           # Reconstruct clean URL
           clean_url = urllib.parse.urlunparse(parsed)
           return clean_url
           
       except Exception:
           return None

Caching Utilities
----------------

Result Caching
~~~~~~~~~~~~~~

.. code-block:: python

   import functools
   import hashlib
   import json
   import pickle
   from pathlib import Path
   
   def cache_analysis_result(cache_dir: str = ".cache"):
       """Decorator for caching analysis results"""
       def decorator(func):
           @functools.wraps(func)
           def wrapper(*args, **kwargs):
               # Create cache directory
               cache_path = Path(cache_dir)
               cache_path.mkdir(exist_ok=True)
               
               # Generate cache key
               cache_key = hashlib.md5(
                   json.dumps([str(arg) for arg in args] + 
                             [f"{k}={v}" for k, v in kwargs.items()]).encode()
               ).hexdigest()
               
               cache_file = cache_path / f"{func.__name__}_{cache_key}.cache"
               
               # Check if cached result exists
               if cache_file.exists():
                   try:
                       with open(cache_file, 'rb') as f:
                           return pickle.load(f)
                   except Exception:
                       # Cache corrupted, remove it
                       cache_file.unlink()
               
               # Execute function and cache result
               result = func(*args, **kwargs)
               
               try:
                   with open(cache_file, 'wb') as f:
                       pickle.dump(result, f)
               except Exception:
                   # Failed to cache, continue without caching
                   pass
               
               return result
           return wrapper
       return decorator
   
   # Usage
   @cache_analysis_result()
   def expensive_analysis(apk_path: str) -> Dict[str, Any]:
       """Expensive analysis function with caching"""
       # Perform expensive computation
       time.sleep(5)  # Simulate expensive operation
       return {'result': 'analysis_complete'}

Performance Monitoring
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import time
   import functools
   
   def monitor_performance(func):
       """Decorator to monitor function performance"""
       @functools.wraps(func)
       def wrapper(*args, **kwargs):
           start_time = time.time()
           memory_start = get_memory_usage()  # Custom function
           
           try:
               result = func(*args, **kwargs)
               success = True
           except Exception as e:
               result = None
               success = False
               raise
           finally:
               end_time = time.time()
               memory_end = get_memory_usage()
               
               # Log performance metrics
               execution_time = end_time - start_time
               memory_delta = memory_end - memory_start
               
               print(f"Function {func.__name__}:")
               print(f"  Execution time: {execution_time:.2f}s")
               print(f"  Memory change: {memory_delta:.2f}MB")
               print(f"  Success: {success}")
           
           return result
       return wrapper
   
   def get_memory_usage() -> float:
       """Get current memory usage in MB"""
       try:
           import psutil
           process = psutil.Process()
           return process.memory_info().rss / 1024 / 1024
       except ImportError:
           return 0.0

Utility Integration Examples
---------------------------

Combining Utilities in Analysis Modules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dexray_insight.Utils.file_utils import dump_json, split_path_file_extension
   from dexray_insight.Utils.androguardObjClass import Androguard_Obj
   from dexray_insight.Utils.log import set_logger
   
   class CustomAnalysisModule:
       def __init__(self, config):
           self.config = config
           self.logger = logging.getLogger(__name__)
       
       def analyze(self, apk_path: str, context: AnalysisContext):
           # Validate APK path
           if not validate_apk_path(apk_path):
               raise ValueError(f"Invalid APK path: {apk_path}")
           
           # Extract filename components
           base_dir, name, ext = split_path_file_extension(apk_path)
           
           # Initialize Androguard analysis
           androguard_obj = Androguard_Obj(apk_path)
           
           if not androguard_obj.is_valid_apk():
               raise ValueError("Invalid APK file")
           
           # Perform analysis
           results = self._perform_custom_analysis(androguard_obj)
           
           # Sanitize and save results
           sanitized_name = sanitize_filename(name)
           output_file = f"custom_analysis_{sanitized_name}.json"
           dump_json(output_file, results)
           
           return results

Error Handling Utilities
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   def safe_extract_urls(text: str) -> List[str]:
       """Safely extract URLs with error handling"""
       try:
           urls = extract_urls(text)
           # Sanitize URLs
           clean_urls = []
           for url in urls:
               clean_url = sanitize_url(url)
               if clean_url:
                   clean_urls.append(clean_url)
           return clean_urls
       except Exception as e:
           logging.warning(f"Failed to extract URLs: {e}")
           return []
   
   def safe_analyze_permissions(permissions: List[str]) -> Dict[str, Any]:
       """Safely analyze permissions with error handling"""
       try:
           return categorize_permissions(permissions)
       except Exception as e:
           logging.error(f"Failed to analyze permissions: {e}")
           return {'dangerous': [], 'normal': [], 'custom': [], 'system': []}

These utilities provide the foundation for reliable and consistent APK analysis throughout the Dexray Insight framework. They handle common edge cases, provide error recovery mechanisms, and ensure data integrity across the analysis pipeline.