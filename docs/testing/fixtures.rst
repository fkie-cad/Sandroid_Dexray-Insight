Test Fixtures
=============

Dexray Insight's testing framework provides a comprehensive set of fixtures to support different testing scenarios. This guide covers all available fixtures, their usage patterns, and how to create custom fixtures.

Global Fixtures
---------------

Configuration Fixtures
~~~~~~~~~~~~~~~~~~~~~~

These fixtures provide different configuration scenarios for testing:

.. code-block:: python

   @pytest.fixture
   def minimal_config():
       """Minimal configuration for basic testing"""
       return {
           'analysis': {
               'parallel_execution': {'enabled': False, 'max_workers': 1},
               'timeout': {'module_timeout': 60, 'tool_timeout': 120}
           },
           'modules': {
               'apk_overview': {'enabled': True, 'priority': 1},
               'string_analysis': {'enabled': True, 'priority': 10},
               'permission_analysis': {'enabled': True, 'priority': 20}
           },
           'logging': {'level': 'WARNING'}
       }
   
   @pytest.fixture
   def full_config():
       """Complete configuration with all modules enabled"""
       return {
           'analysis': {
               'parallel_execution': {'enabled': True, 'max_workers': 4},
               'timeout': {'module_timeout': 300, 'tool_timeout': 600}
           },
           'modules': {
               'apk_overview': {'enabled': True, 'priority': 1},
               'string_analysis': {'enabled': True, 'priority': 10},
               'permission_analysis': {'enabled': True, 'priority': 20},
               'signature_detection': {'enabled': True, 'priority': 30},
               'manifest_analysis': {'enabled': True, 'priority': 15},
               'library_detection': {'enabled': True, 'priority': 25},
               'tracker_analysis': {'enabled': True, 'priority': 35},
               'behaviour_analysis': {'enabled': True, 'priority': 40},
               'native_analysis': {'enabled': True, 'priority': 50}
           },
           'security': {
               'enable_owasp_assessment': True,
               'assessments': {
                   'sensitive_data': {
                       'key_detection': {'enabled': True}
                   }
               }
           },
           'logging': {'level': 'DEBUG'}
       }
   
   @pytest.fixture
   def performance_config():
       """Configuration optimized for performance testing"""
       return {
           'analysis': {
               'parallel_execution': {'enabled': True, 'max_workers': 8},
               'timeout': {'module_timeout': 30, 'tool_timeout': 60}
           },
           'modules': {
               # Enable only essential modules for performance tests
               'apk_overview': {'enabled': True},
               'string_analysis': {'enabled': True},
               'permission_analysis': {'enabled': True}
           },
           'logging': {'level': 'ERROR'}  # Minimal logging
       }

**Usage Example**:

.. code-block:: python

   def test_basic_analysis(minimal_config):
       """Test basic analysis with minimal configuration"""
       config = Configuration(config_dict=minimal_config)
       engine = AnalysisEngine(config)
       # Test implementation...

Mock Object Fixtures
~~~~~~~~~~~~~~~~~~~~

These fixtures provide mock objects for external dependencies:

.. code-block:: python

   @pytest.fixture
   def mock_androguard_obj():
       """Mock Androguard object with realistic data"""
       mock = MagicMock()
       
       # Basic APK information
       mock.get_package.return_value = "com.example.testapp"
       mock.get_version_name.return_value = "1.0.0"
       mock.get_version_code.return_value = 1
       mock.get_min_sdk_version.return_value = 21
       mock.get_target_sdk_version.return_value = 30
       
       # Permissions
       mock.get_permissions.return_value = [
           "android.permission.INTERNET",
           "android.permission.ACCESS_NETWORK_STATE", 
           "android.permission.CAMERA",
           "android.permission.WRITE_EXTERNAL_STORAGE"
       ]
       
       # Components
       mock.get_activities.return_value = [
           "com.example.testapp.MainActivity",
           "com.example.testapp.SettingsActivity"
       ]
       mock.get_services.return_value = [
           "com.example.testapp.BackgroundService"
       ]
       mock.get_receivers.return_value = [
           "com.example.testapp.BootReceiver"
       ]
       mock.get_providers.return_value = []
       
       # Native libraries
       mock.get_libraries.return_value = [
           "libtest.so",
           "libcrypto.so",
           "libssl.so"
       ]
       
       # Validation
       mock.is_valid_apk.return_value = True
       
       return mock
   
   @pytest.fixture
   def mock_analysis_context():
       """Mock analysis context with common data"""
       from dexray_insight.core.base_classes import AnalysisContext, TemporalPaths
       from pathlib import Path
       
       context = AnalysisContext()
       context.apk_path = "/path/to/test.apk"
       context.module_results = {
           'string_analysis': {
               'urls': ['https://api.example.com', 'http://analytics.com'],
               'ip_addresses': ['192.168.1.1', '8.8.8.8'],
               'domains': ['api.example.com', 'cdn.example.com'],
               'email_addresses': ['contact@example.com'],
               'base64_strings': ['dGVzdCBzdHJpbmc=']
           },
           'permission_analysis': {
               'dangerous_permissions': [
                   'android.permission.CAMERA',
                   'android.permission.ACCESS_FINE_LOCATION'
               ],
               'normal_permissions': [
                   'android.permission.INTERNET',
                   'android.permission.ACCESS_NETWORK_STATE'
               ]
           }
       }
       context.shared_data = {
           'processed_strings': True,
           'analysis_timestamp': '2024-01-15T10:30:00Z'
       }
       
       # Mock temporal paths
       context.temporal_paths = TemporalPaths(
           base_dir=Path("/tmp/analysis"),
           unzipped_dir=Path("/tmp/analysis/unzipped"),
           jadx_dir=Path("/tmp/analysis/jadx"),
           apktool_dir=Path("/tmp/analysis/apktool"),
           logs_dir=Path("/tmp/analysis/logs")
       )
       
       return context

HTTP Mock Fixtures
~~~~~~~~~~~~~~~~~~

Mock external API calls for signature detection and other services:

.. code-block:: python

   @pytest.fixture
   def mock_virustotal_api():
       """Mock VirusTotal API responses"""
       responses = {
           'clean_file': {
               'response_code': 1,
               'resource': 'test_hash',
               'scan_id': 'test_scan_id',
               'positives': 0,
               'total': 70,
               'scan_date': '2024-01-15 10:30:00',
               'permalink': 'https://virustotal.com/analysis/test',
               'scans': {
                   'Avira': {'detected': False, 'version': '1.0', 'result': None},
                   'Kaspersky': {'detected': False, 'version': '2.0', 'result': None}
               }
           },
           'malware_file': {
               'response_code': 1,
               'resource': 'malware_hash',
               'positives': 15,
               'total': 70,
               'scan_date': '2024-01-15 10:30:00',
               'scans': {
                   'Avira': {'detected': True, 'result': 'Android.Trojan.Banker'},
                   'Kaspersky': {'detected': True, 'result': 'Trojan.AndroidOS.Boogr'},
                   'McAfee': {'detected': False, 'result': None}
               }
           }
       }
       
       with patch('requests.get') as mock_get, \
            patch('requests.post') as mock_post:
           
           def get_side_effect(url, **kwargs):
               mock_response = Mock()
               if 'malware' in url:
                   mock_response.json.return_value = responses['malware_file']
               else:
                   mock_response.json.return_value = responses['clean_file']
               mock_response.status_code = 200
               return mock_response
           
           mock_get.side_effect = get_side_effect
           mock_post.return_value.json.return_value = {'response_code': 1, 'scan_id': 'test'}
           mock_post.return_value.status_code = 200
           
           yield {'get': mock_get, 'post': mock_post, 'responses': responses}
   
   @pytest.fixture
   def mock_exodus_api():
       """Mock Exodus Privacy API for tracker detection"""
       tracker_data = {
           'trackers': {
               'google_analytics': {
                   'id': 1,
                   'name': 'Google Analytics',
                   'description': 'Google Analytics is a web analytics service',
                   'creation_date': '2018-01-01',
                   'code_signature': 'com.google.android.gms.analytics',
                   'network_signature': 'google-analytics.com',
                   'website': 'https://analytics.google.com',
                   'categories': ['Analytics']
               },
               'facebook_ads': {
                   'id': 2, 
                   'name': 'Facebook Ads',
                   'description': 'Facebook advertising platform',
                   'creation_date': '2018-01-01',
                   'code_signature': 'com.facebook.ads',
                   'network_signature': 'facebook.com',
                   'website': 'https://facebook.com',
                   'categories': ['Advertisement']
               }
           }
       }
       
       with patch('requests.get') as mock_get:
           mock_response = Mock()
           mock_response.json.return_value = tracker_data
           mock_response.status_code = 200
           mock_get.return_value = mock_response
           
           yield {'get': mock_get, 'data': tracker_data}

Synthetic APK Fixtures
----------------------

Basic APK Fixtures
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def synthetic_apk_builder():
       """APK builder for creating synthetic test APKs"""
       from tests.utils.apk_builder import SyntheticApkBuilder
       return SyntheticApkBuilder()
   
   @pytest.fixture
   def basic_synthetic_apk(synthetic_apk_builder, tmp_path):
       """Basic synthetic APK with minimal components"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.test.basic",
           version_name="1.0.0",
           version_code=1,
           framework="Native",
           permissions=[
               "android.permission.INTERNET",
               "android.permission.ACCESS_NETWORK_STATE"
           ],
           activities=["MainActivity"],
           strings=["https://api.example.com", "test@example.com"]
       )
       
       yield str(apk_path)
       
       # Cleanup
       if apk_path.exists():
           apk_path.unlink()
   
   @pytest.fixture
   def complex_synthetic_apk(synthetic_apk_builder, tmp_path):
       """Complex synthetic APK with many components"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.test.complex",
           version_name="2.1.0",
           version_code=21,
           framework="Native",
           permissions=[
               "android.permission.INTERNET",
               "android.permission.CAMERA",
               "android.permission.ACCESS_FINE_LOCATION",
               "android.permission.READ_CONTACTS",
               "android.permission.WRITE_EXTERNAL_STORAGE",
               "android.permission.RECORD_AUDIO"
           ],
           activities=[
               "MainActivity", 
               "SettingsActivity",
               "CameraActivity"
           ],
           services=["BackgroundService", "LocationService"],
           receivers=["BootReceiver", "NetworkReceiver"],
           providers=["DataProvider"],
           native_libraries=["libtest.so", "libcrypto.so"],
           strings=[
               "https://api.example.com/v1",
               "https://analytics.tracking.com",
               "192.168.1.100",
               "8.8.8.8", 
               "admin@example.com",
               "support@company.com",
               "dGVzdCBzdHJpbmc=",  # Base64: "test string"
               "cGFzc3dvcmQ=",      # Base64: "password"
               "API_KEY_12345",
               "SECRET_TOKEN_ABCDEF"
           ]
       )
       
       yield str(apk_path)
       
       # Cleanup
       if apk_path.exists():
           apk_path.unlink()

Framework-Specific APK Fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def flutter_apk(synthetic_apk_builder, tmp_path):
       """Synthetic Flutter APK"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.test.flutter",
           framework="Flutter",
           version_name="1.0.0",
           native_libraries=[
               "libflutter.so",
               "libapp.so",
               "lib arm64-v8a/libflutter.so"
           ],
           activities=["io.flutter.embedding.android.FlutterActivity"],
           strings=[
               "flutter",
               "dart:ui",
               "Flutter Engine",
               "https://flutter.dev/api"
           ]
       )
       
       yield str(apk_path)
       if apk_path.exists():
           apk_path.unlink()
   
   @pytest.fixture
   def react_native_apk(synthetic_apk_builder, tmp_path):
       """Synthetic React Native APK"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.test.reactnative",
           framework="React Native",
           version_name="1.0.0",
           native_libraries=[
               "libreactnativejni.so",
               "libhermes.so",
               "libjsc.so"
           ],
           activities=["com.facebook.react.ReactActivity"],
           strings=[
               "React Native",
               "javascript",
               "metro",
               "https://reactnative.dev"
           ]
       )
       
       yield str(apk_path)
       if apk_path.exists():
           apk_path.unlink()
   
   @pytest.fixture
   def xamarin_apk(synthetic_apk_builder, tmp_path):
       """Synthetic Xamarin APK"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.test.xamarin",
           framework="Xamarin",
           version_name="1.0.0",
           native_libraries=[
               "libmonodroid.so",
               "libmonosgen-2.0.so",
               "libxamarin-app.so"
           ],
           activities=["crc64.MainActivity"],
           strings=[
               "Xamarin",
               "Mono",
               "System.dll",
               "mscorlib.dll"
           ]
       )
       
       yield str(apk_path)
       if apk_path.exists():
           apk_path.unlink()

Specialized Test Fixtures
-------------------------

Security Testing Fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def malware_like_apk(synthetic_apk_builder, tmp_path):
       """APK with malware-like characteristics"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.suspicious.app",
           version_name="1.0.0",
           permissions=[
               "android.permission.READ_CONTACTS",
               "android.permission.READ_SMS",
               "android.permission.SEND_SMS",
               "android.permission.ACCESS_FINE_LOCATION",
               "android.permission.CAMERA",
               "android.permission.RECORD_AUDIO",
               "android.permission.WRITE_EXTERNAL_STORAGE",
               "android.permission.SYSTEM_ALERT_WINDOW"
           ],
           activities=["MainActivity", "HiddenActivity"],
           services=["StealthService"],
           receivers=["BootReceiver", "SmsReceiver"],
           strings=[
               "https://malicious-c2.com/upload",
               "http://evil-server.net/data",
               "credit_card_number",
               "social_security_number",
               "password123",
               "admin_password",
               "192.168.1.100",
               "10.0.0.1",
               # Base64 encoded suspicious strings
               "cGFzc3dvcmQ=",           # "password"
               "YWRtaW5fcGFzc3dvcmQ=",   # "admin_password"
               "c2VjcmV0X2tleQ==",       # "secret_key"
               # Fake API keys and tokens
               "AIzaSyDexampleAPIkey123456789",
               "ghp_exampleGitHubToken123456789",
               "xoxb-slack-bot-token-example",
               "sk_test_stripe_key_example123"
           ],
           intent_filters=[
               {
                   "action": "android.intent.action.BOOT_COMPLETED",
                   "category": "android.intent.category.DEFAULT"
               },
               {
                   "action": "android.provider.Telephony.SMS_RECEIVED",
                   "priority": "1000"
               }
           ]
       )
       
       yield str(apk_path)
       if apk_path.exists():
           apk_path.unlink()
   
   @pytest.fixture
   def privacy_invasive_apk(synthetic_apk_builder, tmp_path):
       """APK with privacy-invasive patterns"""
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.privacy.invasive",
           permissions=[
               "android.permission.ACCESS_FINE_LOCATION",
               "android.permission.READ_CONTACTS",
               "android.permission.READ_PHONE_STATE",
               "android.permission.GET_ACCOUNTS",
               "android.permission.READ_CALENDAR"
           ],
           strings=[
               "https://analytics.tracking-company.com/collect",
               "device_id",
               "imei_number", 
               "phone_number",
               "contact_list",
               "location_data",
               "user_behavior"
           ],
           # Include multiple tracking libraries
           tracking_libraries=[
               "com.google.android.gms.analytics",
               "com.facebook.appevents",
               "com.flurry.android",
               "com.crashlytics.android"
           ]
       )
       
       yield str(apk_path)
       if apk_path.exists():
           apk_path.unlink()

Performance Testing Fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def large_apk(synthetic_apk_builder, tmp_path):
       """Large APK for performance testing"""
       # Generate many strings to simulate large APK
       many_strings = []
       for i in range(1000):
           many_strings.extend([
               f"https://api{i}.example.com",
               f"user{i}@example.com",
               f"192.168.1.{i % 255}",
               f"string_pattern_{i}",
               f"base64_encoded_{i}=" 
           ])
       
       # Generate many activities
       many_activities = [f"Activity{i}" for i in range(50)]
       
       # Generate many permissions
       many_permissions = [
           "android.permission.INTERNET",
           "android.permission.ACCESS_NETWORK_STATE",
           "android.permission.WRITE_EXTERNAL_STORAGE"
       ]
       many_permissions.extend([f"com.example.CUSTOM_PERM_{i}" for i in range(20)])
       
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.test.large",
           version_name="1.0.0",
           permissions=many_permissions,
           activities=many_activities,
           services=[f"Service{i}" for i in range(20)],
           receivers=[f"Receiver{i}" for i in range(10)],
           native_libraries=[f"lib{i}.so" for i in range(10)],
           strings=many_strings
       )
       
       yield str(apk_path)
       if apk_path.exists():
           apk_path.unlink()
   
   @pytest.fixture
   def multiple_synthetic_apks(synthetic_apk_builder, tmp_path):
       """Multiple APKs for parallel processing tests"""
       apks = []
       
       for i in range(5):
           apk_path = synthetic_apk_builder.build_apk(
               output_dir=tmp_path,
               package_name=f"com.test.parallel{i}",
               version_name="1.0.0",
               framework="Native",
               permissions=["android.permission.INTERNET"],
               activities=[f"MainActivity{i}"],
               strings=[f"https://api{i}.example.com"]
           )
           apks.append(str(apk_path))
       
       yield apks
       
       # Cleanup all APKs
       for apk_path in apks:
           path_obj = Path(apk_path)
           if path_obj.exists():
               path_obj.unlink()

Data Fixtures
-------------

Sample Result Fixtures
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def sample_apk_overview_result():
       """Sample APK overview analysis result"""
       from dexray_insight.results.apk_overview_results import ApkOverviewResult
       from dexray_insight.core.base_classes import AnalysisStatus
       
       return ApkOverviewResult(
           module_name="apk_overview",
           status=AnalysisStatus.SUCCESS,
           execution_time=2.5,
           package_name="com.example.testapp",
           version_name="1.0.0",
           version_code=1,
           min_sdk_version=21,
           target_sdk_version=30,
           permissions=[
               "android.permission.INTERNET",
               "android.permission.CAMERA",
               "android.permission.ACCESS_FINE_LOCATION"
           ],
           activities=[
               "com.example.testapp.MainActivity",
               "com.example.testapp.SettingsActivity"
           ],
           services=["com.example.testapp.BackgroundService"],
           receivers=["com.example.testapp.BootReceiver"],
           providers=[],
           native_libraries=["libtest.so", "libcrypto.so"],
           framework="Native"
       )
   
   @pytest.fixture
   def sample_string_analysis_result():
       """Sample string analysis result"""
       from dexray_insight.results.string_analysis_results import StringAnalysisResult
       from dexray_insight.core.base_classes import AnalysisStatus
       
       return StringAnalysisResult(
           module_name="string_analysis",
           status=AnalysisStatus.SUCCESS,
           execution_time=5.2,
           urls=[
               "https://api.example.com/v1",
               "https://analytics.tracking.com",
               "http://cdn.example.com"
           ],
           ip_addresses=["192.168.1.1", "8.8.8.8", "1.1.1.1"],
           email_addresses=["contact@example.com", "support@company.org"],
           domains=["api.example.com", "analytics.tracking.com", "cdn.example.com"],
           base64_strings=["dGVzdCBzdHJpbmc=", "cGFzc3dvcmQ="],
           total_strings=1247
       )
   
   @pytest.fixture
   def sample_security_assessment_result():
       """Sample security assessment result"""
       from dexray_insight.results.security_assessment_results import SecurityAssessmentResult
       from dexray_insight.core.base_classes import AnalysisStatus
       
       return SecurityAssessmentResult(
           module_name="security_assessment",
           status=AnalysisStatus.SUCCESS,
           execution_time=12.8,
           risk_level="HIGH",
           vulnerability_count=5,
           owasp_findings=[
               {
                   'category': 'M2-Insecure-Data-Storage',
                   'description': 'Hardcoded API key detected in strings',
                   'severity': 'HIGH',
                   'evidence': 'AIzaSyDexampleAPIkey123456789'
               },
               {
                   'category': 'M4-Insecure-Authentication',
                   'description': 'Hardcoded password found',
                   'severity': 'CRITICAL',
                   'evidence': 'admin_password'
               }
           ],
           hardcoded_secrets=[
               {
                   'type': 'Google API Key',
                   'value': 'AIzaSyDexampleAPIkey123456789',
                   'severity': 'HIGH',
                   'location': 'strings.xml:42',
                   'context': 'API configuration'
               },
               {
                   'type': 'Hardcoded Password',
                   'value': 'admin_password',
                   'severity': 'CRITICAL',
                   'location': 'AuthManager.java:156',
                   'context': 'Authentication logic'
               }
           ],
           recommendations=[
               "Remove hardcoded API keys and use secure configuration",
               "Implement proper password management",
               "Review data storage security"
           ]
       )

Test Environment Fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture(scope="session")
   def test_environment():
       """Set up test environment configuration"""
       import os
       import tempfile
       from pathlib import Path
       
       # Create temporary directories
       temp_base = Path(tempfile.mkdtemp(prefix="dexray_test_"))
       
       env_config = {
           'temp_dir': temp_base,
           'output_dir': temp_base / "outputs",
           'cache_dir': temp_base / "cache",
           'logs_dir': temp_base / "logs"
       }
       
       # Create directories
       for dir_path in env_config.values():
           if isinstance(dir_path, Path):
               dir_path.mkdir(exist_ok=True)
       
       # Set environment variables
       original_env = {}
       test_env_vars = {
           'DEXRAY_TEST_MODE': 'true',
           'DEXRAY_TEMP_DIR': str(env_config['temp_dir']),
           'DEXRAY_OUTPUT_DIR': str(env_config['output_dir']),
           'NO_COLOR': '1'  # Disable colored output in tests
       }
       
       for key, value in test_env_vars.items():
           original_env[key] = os.environ.get(key)
           os.environ[key] = value
       
       yield env_config
       
       # Cleanup
       import shutil
       shutil.rmtree(temp_base, ignore_errors=True)
       
       # Restore environment variables
       for key, original_value in original_env.items():
           if original_value is None:
               os.environ.pop(key, None)
           else:
               os.environ[key] = original_value
   
   @pytest.fixture
   def isolated_filesystem(tmp_path):
       """Isolated filesystem for file operations"""
       import os
       original_cwd = os.getcwd()
       
       # Change to temporary directory
       os.chdir(tmp_path)
       
       # Create common test directories
       (tmp_path / "inputs").mkdir()
       (tmp_path / "outputs").mkdir()
       (tmp_path / "temp").mkdir()
       
       yield tmp_path
       
       # Restore original working directory
       os.chdir(original_cwd)

Parameterized Fixtures
----------------------

Multi-Configuration Fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture(params=[
       'minimal_config',
       'full_config', 
       'performance_config'
   ])
   def various_configs(request):
       """Fixture providing different configuration scenarios"""
       return request.getfixturevalue(request.param)
   
   @pytest.fixture(params=[
       ('Native', []),
       ('Flutter', ['libflutter.so', 'libapp.so']),
       ('React Native', ['libreactnativejni.so', 'libhermes.so']),
       ('Xamarin', ['libmonodroid.so', 'libmonosgen-2.0.so']),
       ('Unity', ['libunity.so', 'libil2cpp.so'])
   ])
   def framework_apk_data(request):
       """Framework-specific APK test data"""
       framework, native_libs = request.param
       return {
           'framework': framework,
           'native_libraries': native_libs,
           'package_name': f"com.test.{framework.lower().replace(' ', '')}",
           'activities': [f"com.{framework.lower()}.MainActivity"] if framework != 'Native' else ['MainActivity']
       }
   
   @pytest.fixture(params=[1, 4, 8])
   def parallel_worker_counts(request):
       """Different parallel worker configurations"""
       return {
           'analysis': {
               'parallel_execution': {
                   'enabled': True,
                   'max_workers': request.param
               }
           }
       }

APK Complexity Levels
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture(params=[
       {
           'name': 'simple',
           'permissions': 3,
           'activities': 2,
           'strings': 20,
           'native_libs': 1
       },
       {
           'name': 'medium',
           'permissions': 8,
           'activities': 5,
           'strings': 100,
           'native_libs': 3
       },
       {
           'name': 'complex',
           'permissions': 15,
           'activities': 12,
           'strings': 500,
           'native_libs': 8
       }
   ])
   def apk_complexity_levels(request, synthetic_apk_builder, tmp_path):
       """APKs with different complexity levels"""
       params = request.param
       
       # Generate appropriate amounts of test data
       permissions = [
           "android.permission.INTERNET",
           "android.permission.ACCESS_NETWORK_STATE"
       ] + [f"com.example.PERM_{i}" for i in range(params['permissions'] - 2)]
       
       activities = [f"Activity{i}" for i in range(params['activities'])]
       
       strings = [f"https://api{i}.example.com" for i in range(params['strings'])]
       
       native_libs = [f"lib{i}.so" for i in range(params['native_libs'])]
       
       apk_path = synthetic_apk_builder.build_apk(
           output_dir=tmp_path,
           package_name=f"com.test.{params['name']}",
           version_name="1.0.0",
           permissions=permissions,
           activities=activities,
           strings=strings,
           native_libraries=native_libs
       )
       
       yield {
           'apk_path': str(apk_path),
           'complexity': params['name'],
           'expected_counts': params
       }
       
       if apk_path.exists():
           apk_path.unlink()

Custom Fixture Creation
----------------------

Creating Module-Specific Fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # For string analysis module tests
   @pytest.fixture
   def string_analysis_test_data():
       """Test data for string analysis module"""
       return {
           'input_strings': [
               "Visit https://example.com for more info",
               "Contact us at support@company.org",
               "Server IP: 192.168.1.100",
               "Base64 data: dGVzdCBkYXRh",
               "API endpoint: https://api.service.com/v2",
               "Debug server: http://10.0.0.1:8080",
               "Email: admin@test.local"
           ],
           'expected_urls': [
               "https://example.com",
               "https://api.service.com/v2", 
               "http://10.0.0.1:8080"
           ],
           'expected_emails': [
               "support@company.org",
               "admin@test.local"
           ],
           'expected_ips': [
               "192.168.1.100",
               "10.0.0.1"
           ],
           'expected_base64': [
               "dGVzdCBkYXRh"
           ]
       }
   
   # For security assessment tests
   @pytest.fixture
   def security_test_secrets():
       """Test secrets for security assessment"""
       return {
           'api_keys': [
               "AIzaSyDexampleGoogleAPIkey123456789",
               "ghp_exampleGitHubPersonalAccessToken123",
               "xoxb-example-slack-bot-token-123456"
           ],
           'passwords': [
               "password123",
               "admin_password",
               "default_pass"
           ],
           'certificates': [
               "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...",
               "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKC..."
           ],
           'database_urls': [
               "mongodb://user:pass@localhost:27017/db",
               "postgresql://admin:secret@db.example.com:5432/app"
           ]
       }

Factory Fixtures
~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def apk_factory(synthetic_apk_builder, tmp_path):
       """Factory for creating APKs with custom parameters"""
       created_apks = []
       
       def create_apk(**kwargs):
           # Default parameters
           defaults = {
               'output_dir': tmp_path,
               'package_name': 'com.test.factory',
               'version_name': '1.0.0',
               'framework': 'Native',
               'permissions': ['android.permission.INTERNET'],
               'activities': ['MainActivity']
           }
           
           # Merge with provided parameters
           defaults.update(kwargs)
           
           apk_path = synthetic_apk_builder.build_apk(**defaults)
           created_apks.append(apk_path)
           return str(apk_path)
       
       yield create_apk
       
       # Cleanup all created APKs
       for apk_path in created_apks:
           if apk_path.exists():
               apk_path.unlink()
   
   @pytest.fixture
   def mock_factory():
       """Factory for creating various mock objects"""
       def create_mock_result(module_name, status='SUCCESS', **kwargs):
           from dexray_insight.core.base_classes import BaseResult, AnalysisStatus
           
           mock_result = Mock(spec=BaseResult)
           mock_result.module_name = module_name
           mock_result.status = getattr(AnalysisStatus, status)
           mock_result.execution_time = kwargs.get('execution_time', 1.0)
           mock_result.error_message = kwargs.get('error_message')
           
           # Add custom attributes
           for key, value in kwargs.items():
               if key not in ['execution_time', 'error_message']:
                   setattr(mock_result, key, value)
           
           return mock_result
       
       def create_mock_context(apk_path="/test/app.apk", **module_results):
           from dexray_insight.core.base_classes import AnalysisContext
           
           context = AnalysisContext()
           context.apk_path = apk_path
           context.module_results = module_results
           context.shared_data = {}
           
           return context
       
       return {
           'result': create_mock_result,
           'context': create_mock_context
       }

Using Fixtures Effectively
--------------------------

Fixture Composition
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def complete_analysis_setup(
       full_config, 
       complex_synthetic_apk, 
       mock_virustotal_api,
       test_environment
   ):
       """Complete setup for full analysis testing"""
       from dexray_insight.core.configuration import Configuration
       from dexray_insight.core.analysis_engine import AnalysisEngine
       
       # Configure analysis engine
       config = Configuration(config_dict=full_config)
       engine = AnalysisEngine(config)
       
       return {
           'engine': engine,
           'apk_path': complex_synthetic_apk,
           'config': config,
           'environment': test_environment,
           'mocked_apis': mock_virustotal_api
       }
   
   def test_complete_analysis_with_mocks(complete_analysis_setup):
       """Test complete analysis with all mocks"""
       setup = complete_analysis_setup
       
       # Run analysis
       results = setup['engine'].analyze_apk(setup['apk_path'])
       
       # Verify results
       assert results is not None
       assert results.apk_overview is not None
       assert results.string_analysis is not None
       
       # Verify API mocks were called
       setup['mocked_apis']['get'].assert_called()

Fixture Scoping and Performance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Session-scoped fixture for expensive setup
   @pytest.fixture(scope="session")
   def expensive_test_data():
       """Expensive test data created once per test session"""
       # This runs once for the entire test session
       large_data = generate_large_test_dataset()
       return large_data
   
   # Module-scoped fixture for per-module setup
   @pytest.fixture(scope="module")
   def module_test_environment():
       """Test environment per module"""
       # This runs once per test module
       env = setup_test_environment()
       yield env
       cleanup_test_environment(env)
   
   # Function-scoped fixture (default) for per-test setup
   @pytest.fixture
   def test_specific_data():
       """Data specific to each test"""
       # This runs for each test function
       return generate_test_specific_data()

Best Practices for Fixtures
---------------------------

**Naming and Organization**:

1. **Descriptive names** - Fixture names should clearly indicate what they provide
2. **Consistent patterns** - Use consistent naming patterns across the test suite
3. **Logical grouping** - Group related fixtures together
4. **Clear documentation** - Document fixture purpose and usage

**Resource Management**:

1. **Proper cleanup** - Always clean up resources in fixture teardown
2. **Appropriate scoping** - Use the right fixture scope for performance
3. **Avoid side effects** - Fixtures should not have unintended side effects
4. **Isolation** - Each fixture should be independent

**Performance Considerations**:

1. **Cache expensive operations** - Use session or module scoped fixtures for expensive setup
2. **Lazy loading** - Only create resources when actually needed
3. **Parallel safety** - Ensure fixtures work correctly with parallel test execution
4. **Memory management** - Clean up large objects to prevent memory issues

The comprehensive fixture system in Dexray Insight enables thorough testing across all components while maintaining test isolation and performance.