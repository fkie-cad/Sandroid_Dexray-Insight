Writing Tests
=============

This guide provides comprehensive instructions for writing effective tests for Dexray Insight. It covers test patterns, best practices, and specific examples for different types of testing scenarios.

Test Structure and Organization
-------------------------------

File Organization
~~~~~~~~~~~~~~~~

Follow the established directory structure when creating new tests:

.. code-block:: text

   tests/
   ├── unit/                    # Unit tests
   │   ├── core/               # Core framework components
   │   ├── modules/            # Analysis modules
   │   ├── utils/              # Utility functions
   │   └── results/            # Result classes
   ├── integration/            # Integration tests
   │   ├── analysis_flow/      # End-to-end analysis tests
   │   └── module_interaction/ # Inter-module tests
   └── utils/                  # Testing utilities
       └── test_helpers.py     # Shared test helpers

Naming Conventions
~~~~~~~~~~~~~~~~~

**Test Files**: ``test_<module_name>.py``

.. code-block:: bash

   # Good examples
   test_configuration.py
   test_string_analysis.py
   test_file_utils.py
   
   # Avoid
   configuration_tests.py
   test_config.py  # Too abbreviated

**Test Classes**: ``Test<ComponentName>``

.. code-block:: python

   class TestConfiguration:
       """Tests for Configuration class"""
       pass
   
   class TestStringAnalysisModule:
       """Tests for StringAnalysisModule"""
       pass

**Test Methods**: ``test_<should>_<when>_<given>``

.. code-block:: python

   def test_should_return_package_name_when_valid_apk_provided(self):
       """Test that package name is returned when valid APK is provided"""
       pass
   
   def test_should_raise_error_when_invalid_file_path_given(self):
       """Test that error is raised when invalid file path is given"""  
       pass

Writing Unit Tests
------------------

Basic Unit Test Structure
~~~~~~~~~~~~~~~~~~~~~~~~

Follow the Arrange-Act-Assert (AAA) pattern:

.. code-block:: python

   import pytest
   from unittest.mock import Mock, patch
   from dexray_insight.Utils.file_utils import split_path_file_extension
   
   class TestFileUtils:
       """Unit tests for file utility functions"""
       
       @pytest.mark.unit
       def test_should_split_path_correctly_when_valid_path_given(self):
           """Test that path is split correctly when valid path is given"""
           # Arrange
           file_path = "/path/to/example.apk"
           expected_dir = "/path/to"
           expected_name = "example"
           expected_ext = "apk"
           
           # Act
           actual_dir, actual_name, actual_ext = split_path_file_extension(file_path)
           
           # Assert
           assert actual_dir == expected_dir
           assert actual_name == expected_name  
           assert actual_ext == expected_ext

Parametrized Tests
~~~~~~~~~~~~~~~~~

Use parametrization for testing multiple scenarios:

.. code-block:: python

   import pytest
   
   class TestFileUtils:
       
       @pytest.mark.unit
       @pytest.mark.parametrize("file_path,expected_dir,expected_name,expected_ext", [
           ("/path/to/app.apk", "/path/to", "app", "apk"),
           ("/root/complex.name.apk", "/root", "complex.name", "apk"),
           ("./relative.apk", ".", "relative", "apk"),
           ("/app", "/", "app", ""),
           ("", ".", "", ""),
       ])
       def test_split_path_file_extension_various_inputs(
           self, file_path, expected_dir, expected_name, expected_ext
       ):
           """Test split_path_file_extension with various input formats"""
           # Act
           dir_path, name, ext = split_path_file_extension(file_path)
           
           # Assert
           assert dir_path == expected_dir
           assert name == expected_name
           assert ext == expected_ext

Exception Testing
~~~~~~~~~~~~~~~~

Test both expected exceptions and error handling:

.. code-block:: python

   import pytest
   from dexray_insight.core.configuration import Configuration
   
   class TestConfiguration:
       
       @pytest.mark.unit
       def test_should_raise_file_not_found_when_nonexistent_config_file_given(self):
           """Test that FileNotFoundError is raised for nonexistent config file"""
           # Arrange
           nonexistent_path = "/nonexistent/config.yaml"
           
           # Act & Assert
           with pytest.raises(FileNotFoundError, match="Configuration file not found"):
               Configuration(config_path=nonexistent_path)
       
       @pytest.mark.unit
       def test_should_handle_invalid_yaml_gracefully(self):
           """Test that invalid YAML is handled gracefully"""
           # Arrange
           invalid_yaml = "invalid: yaml: content: ["
           
           with patch('builtins.open', mock_open(read_data=invalid_yaml)):
               # Act
               with pytest.raises(ValueError, match="Invalid YAML format"):
                   Configuration(config_path="invalid.yaml")

Mocking External Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Mock external dependencies to isolate unit tests:

.. code-block:: python

   import pytest
   from unittest.mock import Mock, patch, MagicMock
   from dexray_insight.modules.signature_detection import SignatureDetectionModule
   
   class TestSignatureDetectionModule:
       
       @pytest.fixture
       def mock_requests(self):
           """Mock requests library for API calls"""
           with patch('requests.get') as mock_get, \
                patch('requests.post') as mock_post:
               
               # Configure mock responses
               mock_response = Mock()
               mock_response.json.return_value = {
                   'response_code': 1,
                   'positives': 3,
                   'total': 70
               }
               mock_response.status_code = 200
               
               mock_get.return_value = mock_response
               mock_post.return_value = mock_response
               
               yield {'get': mock_get, 'post': mock_post}
       
       @pytest.mark.unit
       def test_should_detect_malware_when_virustotal_returns_positives(
           self, mock_requests, test_configuration
       ):
           """Test malware detection when VirusTotal returns positive results"""
           # Arrange
           module = SignatureDetectionModule(test_configuration)
           apk_hash = "test_hash_123"
           
           # Act
           result = module.check_virustotal(apk_hash)
           
           # Assert
           assert result['detected'] is True
           assert result['positives'] == 3
           assert result['total'] == 70
           
           # Verify API was called correctly
           mock_requests['get'].assert_called_once()
           called_url = mock_requests['get'].call_args[0][0]
           assert apk_hash in called_url

Mock Configuration
~~~~~~~~~~~~~~~~~

Create reusable mock configurations:

.. code-block:: python

   @pytest.fixture
   def minimal_config():
       """Minimal configuration for testing"""
       return {
           'modules': {
               'string_analysis': {'enabled': True},
               'permission_analysis': {'enabled': True}
           },
           'analysis': {
               'parallel_execution': {'enabled': False},
               'timeout': {'module_timeout': 30}
           },
           'logging': {'level': 'DEBUG'}
       }
   
   @pytest.fixture
   def security_focused_config():
       """Configuration focused on security testing"""
       return {
           'modules': {
               'signature_detection': {
                   'enabled': True,
                   'providers': {
                       'virustotal': {'enabled': True, 'api_key': 'test_key'}
                   }
               }
           },
           'security': {
               'enable_owasp_assessment': True,
               'assessments': {
                   'sensitive_data': {
                       'key_detection': {'enabled': True}
                   }
               }
           }
       }

Writing Integration Tests
-------------------------

Module Integration Testing
~~~~~~~~~~~~~~~~~~~~~~~~~

Test interactions between multiple modules:

.. code-block:: python

   import pytest
   from dexray_insight.core.analysis_engine import AnalysisEngine
   from dexray_insight.core.configuration import Configuration
   from dexray_insight.core.base_classes import AnalysisContext
   
   class TestModuleIntegration:
       
       @pytest.mark.integration
       def test_should_pass_string_results_to_tracker_analysis(
           self, synthetic_apk, test_configuration
       ):
           """Test that string analysis results are passed to tracker analysis"""
           # Arrange
           config = Configuration(config_dict=test_configuration)
           engine = AnalysisEngine(config)
           
           # Act
           results = engine.analyze_apk(synthetic_apk)
           
           # Assert
           assert results.string_analysis is not None
           assert results.tracker_analysis is not None
           
           # Verify string results were used by tracker analysis
           if results.string_analysis.urls:
               # Tracker analysis should have processed URLs
               assert hasattr(results.tracker_analysis, 'processed_urls')
       
       @pytest.mark.integration
       def test_should_integrate_native_strings_with_string_analysis(
           self, synthetic_apk_with_native_libs, test_configuration
       ):
           """Test that native string extraction integrates with string analysis"""
           # Arrange
           config = Configuration(config_dict=test_configuration)
           config.enable_native_analysis = True
           engine = AnalysisEngine(config)
           
           # Act
           results = engine.analyze_apk(synthetic_apk_with_native_libs)
           
           # Assert
           if results.native_analysis and results.native_analysis.total_strings_extracted > 0:
               # Native strings should be available in context
               assert 'native_strings' in results.analysis_context.module_results
               
               # String patterns from native code should be detected
               native_strings = results.analysis_context.module_results['native_strings']
               urls_from_native = [s for s in native_strings if s.startswith('http')]
               
               if urls_from_native:
                   # These URLs should appear in string analysis results
                   assert any(url in results.string_analysis.urls for url in urls_from_native)

End-to-End Testing
~~~~~~~~~~~~~~~~~

Test complete analysis workflows:

.. code-block:: python

   class TestAnalysisWorkflow:
       
       @pytest.mark.integration
       @pytest.mark.slow
       def test_complete_security_analysis_workflow(
           self, complex_synthetic_apk, security_focused_config
       ):
           """Test complete security analysis workflow"""
           # Arrange
           config = Configuration(config_dict=security_focused_config)
           engine = AnalysisEngine(config)
           
           # Act
           results = engine.analyze_apk(complex_synthetic_apk)
           
           # Assert - Verify all expected modules ran
           assert results.apk_overview is not None
           assert results.string_analysis is not None
           assert results.permission_analysis is not None
           assert results.security_assessment is not None
           
           # Verify security assessment used data from other modules
           if results.security_assessment.hardcoded_secrets:
               # Secrets should correlate with string analysis findings
               secret_values = [s['value'] for s in results.security_assessment.hardcoded_secrets]
               string_data = (results.string_analysis.urls + 
                            results.string_analysis.base64_strings)
               
               # At least some secrets should be found in string analysis
               assert any(secret in ' '.join(string_data) for secret in secret_values)
       
       @pytest.mark.integration
       def test_parallel_execution_produces_same_results_as_sequential(
           self, synthetic_apk, test_configuration
       ):
           """Test that parallel execution produces same results as sequential"""
           # Arrange
           sequential_config = test_configuration.copy()
           sequential_config['analysis']['parallel_execution']['enabled'] = False
           
           parallel_config = test_configuration.copy()
           parallel_config['analysis']['parallel_execution']['enabled'] = True
           
           # Act
           sequential_results = AnalysisEngine(Configuration(config_dict=sequential_config)).analyze_apk(synthetic_apk)
           parallel_results = AnalysisEngine(Configuration(config_dict=parallel_config)).analyze_apk(synthetic_apk)
           
           # Assert - Results should be equivalent
           self.assert_results_equivalent(sequential_results, parallel_results)
       
       def assert_results_equivalent(self, results1, results2):
           """Helper to assert two analysis results are equivalent"""
           # Compare key result fields
           assert results1.apk_overview.package_name == results2.apk_overview.package_name
           assert results1.apk_overview.permissions == results2.apk_overview.permissions
           
           # Compare string analysis (order may differ)
           assert set(results1.string_analysis.urls) == set(results2.string_analysis.urls)
           assert set(results1.string_analysis.ip_addresses) == set(results2.string_analysis.ip_addresses)

Writing Tests with Synthetic APKs
---------------------------------

Using the APK Builder
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import pytest
   from tests.utils.apk_builder import SyntheticApkBuilder
   
   class TestWithSyntheticApks:
       
       @pytest.fixture
       def apk_builder(self):
           """APK builder fixture"""
           return SyntheticApkBuilder()
       
       @pytest.mark.synthetic
       def test_should_detect_flutter_framework(self, apk_builder, tmp_path):
           """Test Flutter framework detection with synthetic APK"""
           # Arrange
           apk_path = apk_builder.build_apk(
               output_dir=tmp_path,
               package_name="com.test.flutter",
               framework="Flutter",
               native_libraries=["libflutter.so", "libapp.so"],
               activities=["io.flutter.embedding.android.FlutterActivity"]
           )
           
           # Act
           results = analyze_apk(apk_path)
           
           # Assert
           assert results.apk_overview.framework == "Flutter"
           assert "libflutter.so" in results.apk_overview.native_libraries
           
           # Cleanup
           apk_path.unlink()
       
       @pytest.mark.synthetic
       @pytest.mark.parametrize("framework,expected_libs", [
           ("Flutter", ["libflutter.so", "libapp.so"]),
           ("React Native", ["libreactnativejni.so", "libhermes.so"]),
           ("Xamarin", ["libmonodroid.so", "libmonosgen-2.0.so"]),
           ("Unity", ["libunity.so", "libil2cpp.so"])
       ])
       def test_framework_detection_with_various_frameworks(
           self, apk_builder, tmp_path, framework, expected_libs
       ):
           """Test framework detection with various synthetic frameworks"""
           # Arrange
           apk_path = apk_builder.build_apk(
               output_dir=tmp_path,
               package_name=f"com.test.{framework.lower().replace(' ', '')}",
               framework=framework,
               native_libraries=expected_libs
           )
           
           try:
               # Act
               results = analyze_apk(apk_path)
               
               # Assert
               assert results.apk_overview.framework == framework
               for lib in expected_libs:
                   assert lib in results.apk_overview.native_libraries
           finally:
               # Cleanup
               apk_path.unlink()

Creating Custom Test APKs
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @pytest.fixture
   def malware_like_apk(apk_builder, tmp_path):
       """Create APK with malware-like characteristics for testing"""
       return apk_builder.build_apk(
           output_dir=tmp_path,
           package_name="com.suspicious.app",
           version_name="1.0.0",
           permissions=[
               "android.permission.READ_CONTACTS",
               "android.permission.ACCESS_FINE_LOCATION", 
               "android.permission.CAMERA",
               "android.permission.RECORD_AUDIO",
               "android.permission.SEND_SMS"
           ],
           activities=["MainActivity", "HiddenActivity"],
           services=["BackgroundService"],
           receivers=["BootReceiver"],
           strings=[
               "https://malicious-server.com/collect",
               "credit_card_number",
               "password123",
               "192.168.1.100",
               "dGVzdCBzdHJpbmc="  # Base64 encoded "test string"
           ],
           intent_filters=[
               {
                   "action": "android.intent.action.BOOT_COMPLETED",
                   "category": "android.intent.category.DEFAULT"
               }
           ]
       )
   
   @pytest.mark.synthetic
   def test_security_assessment_detects_suspicious_patterns(malware_like_apk):
       """Test that security assessment detects suspicious patterns"""
       # Act
       results = analyze_apk_with_security_assessment(malware_like_apk)
       
       # Assert
       assert results.security_assessment is not None
       assert results.security_assessment.risk_level in ["HIGH", "CRITICAL"]
       
       # Should detect dangerous permissions
       dangerous_perms = [p for p in results.apk_overview.permissions 
                         if is_dangerous_permission(p)]
       assert len(dangerous_perms) >= 3
       
       # Should detect suspicious URLs
       suspicious_urls = [url for url in results.string_analysis.urls 
                         if "malicious" in url]
       assert len(suspicious_urls) > 0
       
       # Should detect exported components without protection
       security_issues = results.security_assessment.owasp_findings
       exported_issues = [issue for issue in security_issues 
                         if "exported" in issue['description']]
       assert len(exported_issues) > 0

Performance Testing
------------------

Timing and Resource Tests
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import time
   import psutil
   import pytest
   from memory_profiler import profile
   
   class TestPerformance:
       
       @pytest.mark.slow
       @pytest.mark.performance
       def test_analysis_completes_within_time_limit(self, large_synthetic_apk):
           """Test that analysis completes within reasonable time"""
           # Arrange
           max_time_seconds = 300  # 5 minutes
           
           # Act
           start_time = time.time()
           results = analyze_apk(large_synthetic_apk)
           execution_time = time.time() - start_time
           
           # Assert
           assert execution_time < max_time_seconds, f"Analysis took {execution_time:.2f}s, exceeds limit of {max_time_seconds}s"
           assert results is not None
           assert results.apk_overview is not None
       
       @pytest.mark.slow
       @pytest.mark.performance
       def test_memory_usage_stays_within_limits(self, large_synthetic_apk):
           """Test that memory usage stays within acceptable limits"""
           # Arrange
           process = psutil.Process()
           initial_memory = process.memory_info().rss / 1024 / 1024  # MB
           max_memory_increase = 1024  # MB
           
           # Act
           results = analyze_apk(large_synthetic_apk)
           
           # Force garbage collection
           import gc
           gc.collect()
           
           final_memory = process.memory_info().rss / 1024 / 1024  # MB
           memory_increase = final_memory - initial_memory
           
           # Assert
           assert memory_increase < max_memory_increase, f"Memory increased by {memory_increase:.2f}MB, exceeds limit of {max_memory_increase}MB"
           assert results is not None
       
       @pytest.mark.performance
       def test_parallel_analysis_faster_than_sequential(self, multiple_synthetic_apks):
           """Test that parallel analysis is faster than sequential"""
           apks = multiple_synthetic_apks  # List of 4 APK paths
           
           # Sequential analysis
           start_time = time.time()
           sequential_results = []
           for apk in apks:
               result = analyze_apk_sequential(apk)
               sequential_results.append(result)
           sequential_time = time.time() - start_time
           
           # Parallel analysis
           start_time = time.time()
           parallel_results = analyze_apks_parallel(apks)
           parallel_time = time.time() - start_time
           
           # Assert parallel is significantly faster
           speedup_ratio = sequential_time / parallel_time
           assert speedup_ratio > 1.5, f"Parallel analysis only {speedup_ratio:.2f}x faster, expected >1.5x"
           
           # Results should be equivalent
           assert len(sequential_results) == len(parallel_results)

Stress Testing
~~~~~~~~~~~~~

.. code-block:: python

   class TestStressScenarios:
       
       @pytest.mark.stress
       @pytest.mark.slow
       def test_handles_many_concurrent_analyses(self):
           """Test handling many concurrent analysis requests"""
           import threading
           import queue
           
           num_concurrent = 20
           results_queue = queue.Queue()
           errors_queue = queue.Queue()
           
           def analyze_worker(apk_path, worker_id):
               try:
                   result = analyze_apk(f"synthetic_apk_{worker_id}.apk")
                   results_queue.put((worker_id, result))
               except Exception as e:
                   errors_queue.put((worker_id, str(e)))
           
           # Start concurrent analyses
           threads = []
           for i in range(num_concurrent):
               thread = threading.Thread(target=analyze_worker, args=(f"apk_{i}", i))
               thread.start()
               threads.append(thread)
           
           # Wait for completion
           for thread in threads:
               thread.join(timeout=60)  # 1 minute timeout per thread
           
           # Collect results
           successful_analyses = []
           while not results_queue.empty():
               successful_analyses.append(results_queue.get())
           
           failed_analyses = []
           while not errors_queue.empty():
               failed_analyses.append(errors_queue.get())
           
           # Assert most analyses succeeded
           success_rate = len(successful_analyses) / num_concurrent
           assert success_rate >= 0.8, f"Only {success_rate:.1%} analyses succeeded, expected >80%"
           
           # Assert no critical failures
           critical_failures = [error for _, error in failed_analyses if "critical" in error.lower()]
           assert len(critical_failures) == 0, f"Critical failures detected: {critical_failures}"

Test Data Management
-------------------

Creating Test Fixtures
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import pytest
   import json
   from pathlib import Path
   
   @pytest.fixture(scope="session")
   def test_data_dir():
       """Directory containing test data files"""
       return Path(__file__).parent / "fixtures"
   
   @pytest.fixture(scope="session") 
   def sample_analysis_results(test_data_dir):
       """Sample analysis results for testing"""
       results_file = test_data_dir / "sample_results.json"
       with open(results_file) as f:
           return json.load(f)
   
   @pytest.fixture
   def expected_permissions():
       """Expected permissions for test APKs"""
       return [
           "android.permission.INTERNET",
           "android.permission.ACCESS_NETWORK_STATE",
           "android.permission.WRITE_EXTERNAL_STORAGE"
       ]

Cleanup and Resource Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import pytest
   import tempfile
   import shutil
   from pathlib import Path
   
   @pytest.fixture
   def temp_dir():
       """Temporary directory for test files"""
       temp_path = Path(tempfile.mkdtemp())
       yield temp_path
       # Cleanup
       shutil.rmtree(temp_path, ignore_errors=True)
   
   @pytest.fixture
   def temporary_apk_files():
       """List of temporary APK files, cleaned up after test"""
       temp_files = []
       yield temp_files
       # Cleanup
       for file_path in temp_files:
           try:
               Path(file_path).unlink()
           except Exception:
               pass  # Ignore cleanup errors
   
   class TestWithCleanup:
       
       def test_creates_temporary_files(self, temp_dir, temporary_apk_files):
           """Test that creates temporary files"""
           # Create test APK
           test_apk = temp_dir / "test.apk"
           test_apk.write_bytes(b"fake apk content")
           temporary_apk_files.append(str(test_apk))
           
           # Test code here...
           assert test_apk.exists()
           
           # Files will be cleaned up automatically

Debugging Test Failures
-----------------------

Adding Debug Information
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import pytest
   import logging
   
   class TestWithDebugging:
       
       def test_with_debug_output(self, caplog):
           """Test with debug logging captured"""
           # Enable debug logging for test
           with caplog.at_level(logging.DEBUG):
               result = complex_analysis_function()
           
           # Print debug logs on failure
           if not result.is_successful():
               print("Debug logs:")
               for record in caplog.records:
                   print(f"  {record.levelname}: {record.message}")
           
           assert result.is_successful()
       
       def test_with_detailed_assertions(self, synthetic_apk):
           """Test with detailed assertion messages"""
           results = analyze_apk(synthetic_apk)
           
           # Detailed assertion with context
           assert results.apk_overview is not None, \
               f"APK overview missing. Analysis status: {results.status}, Error: {getattr(results, 'error_message', 'None')}"
           
           assert results.apk_overview.package_name, \
               f"Package name missing. APK overview: {results.apk_overview.to_dict()}"

Test Failure Investigation
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   def test_with_failure_investigation(self, synthetic_apk):
       """Test with failure investigation helpers"""
       try:
           results = analyze_apk(synthetic_apk)
           assert results.string_analysis is not None
           assert len(results.string_analysis.urls) > 0
           
       except AssertionError as e:
           # Gather debugging information
           debug_info = {
               'apk_size': Path(synthetic_apk).stat().st_size,
               'apk_readable': Path(synthetic_apk).is_file(),
               'analysis_results': results.to_dict() if 'results' in locals() else None,
               'module_statuses': {
                   module: getattr(results, module).status.name 
                   if hasattr(results, module) and hasattr(getattr(results, module), 'status')
                   else 'MISSING'
                   for module in ['apk_overview', 'string_analysis', 'permission_analysis']
               } if 'results' in locals() else {}
           }
           
           # Print debug info and re-raise
           print(f"Test failed with debug info: {debug_info}")
           raise

Best Practices Summary
---------------------

**Test Design**:

1. **One assertion per test** - Tests should verify one specific behavior
2. **Independent tests** - Tests should not depend on execution order
3. **Descriptive names** - Test names should clearly indicate what is being tested
4. **AAA pattern** - Arrange, Act, Assert structure
5. **Mock external dependencies** - Don't test third-party code

**Test Organization**:

1. **Group related tests** - Use test classes to group related functionality
2. **Share fixtures** - Use pytest fixtures for common test data
3. **Parametrize similar tests** - Avoid code duplication with parametrization
4. **Use appropriate markers** - Mark tests with their category and requirements

**Performance Considerations**:

1. **Mock expensive operations** - File I/O, network calls, external processes
2. **Use synthetic data** - Generate test data rather than relying on real files
3. **Clean up resources** - Always clean up temporary files and objects
4. **Parallel test execution** - Use pytest-xdist for faster test runs

**Debugging**:

1. **Capture logs** - Use caplog fixture to capture and analyze log output
2. **Add debug information** - Print relevant context when tests fail
3. **Use descriptive assertions** - Include context in assertion messages
4. **Test error paths** - Verify error handling and edge cases

Following these guidelines will help you create maintainable, reliable tests that provide confidence in code changes and serve as documentation for expected behavior.