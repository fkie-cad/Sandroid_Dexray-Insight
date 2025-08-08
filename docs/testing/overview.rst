Testing Framework Overview
==========================

Dexray Insight includes a comprehensive testing framework built on pytest that ensures code quality, reliability, and maintainability. The testing framework provides synthetic APK generation, comprehensive fixtures, and unit tests for core functionality.

Testing Architecture
--------------------

The testing framework is organized into several layers:

**Unit Tests**
  Test individual functions and classes in isolation

**Integration Tests**
  Test interaction between components

**Synthetic APK Tests**
  Test analysis modules using generated APK files

**Fixture System**
  Reusable test components and mock objects

Testing Structure
-----------------

The test suite is organized in the ``tests/`` directory:

.. code-block:: text

   tests/
   ├── conftest.py              # Global fixtures and configuration
   ├── pytest.ini               # Pytest configuration
   ├── unit/                    # Unit tests
   │   ├── core/                # Core framework tests
   │   │   ├── test_configuration.py
   │   │   └── test_base_classes.py
   │   └── utils/               # Utility function tests
   │       └── test_file_utils.py
   ├── integration/             # Integration tests
   │   └── test_analysis_flow.py
   ├── fixtures/                # Test fixtures
   │   └── sample_apks/         # Sample APK files for testing
   └── utils/                   # Testing utilities
       └── apk_builder.py       # Synthetic APK generation

Test Configuration
-----------------

**pytest.ini Configuration**:

The testing framework uses a comprehensive pytest configuration:

.. code-block:: ini

   [tool:pytest]
   minversion = 6.0
   testpaths = tests
   python_files = test_*.py *_test.py
   python_classes = Test*
   python_functions = test_*
   addopts = 
       -v
       --tb=short
       --strict-markers
       --disable-warnings
       --color=yes
   markers =
       unit: Unit tests for individual components
       integration: Integration tests for component interaction
       synthetic: Tests using synthetic APK generation
       slow: Tests that take longer than 10 seconds
       requires_tools: Tests requiring external tools (apktool, jadx, radare2)
       network: Tests requiring network connectivity

**Custom Test Markers**:

Tests are categorized using pytest markers:

.. code-block:: python

   import pytest
   
   @pytest.mark.unit
   def test_file_utils():
       """Unit test for file utilities"""
       pass
   
   @pytest.mark.integration
   def test_analysis_pipeline():
       """Integration test for analysis pipeline"""
       pass
   
   @pytest.mark.synthetic
   def test_with_synthetic_apk():
       """Test using synthetic APK"""
       pass
   
   @pytest.mark.slow
   def test_large_apk_analysis():
       """Test that takes significant time"""
       pass

Running Tests
-------------

**Run All Tests**:

.. code-block:: bash

   # Run complete test suite
   pytest
   
   # Run with verbose output
   pytest -v
   
   # Run with coverage report
   pytest --cov=src/dexray_insight --cov-report=html

**Run Specific Test Categories**:

.. code-block:: bash

   # Run only unit tests
   pytest -m unit
   
   # Run only integration tests
   pytest -m integration
   
   # Run tests using synthetic APKs
   pytest -m synthetic
   
   # Skip slow tests
   pytest -m "not slow"
   
   # Run tests that don't require external tools
   pytest -m "not requires_tools"

**Run Specific Test Files**:

.. code-block:: bash

   # Run specific test file
   pytest tests/unit/utils/test_file_utils.py
   
   # Run specific test class
   pytest tests/unit/core/test_configuration.py::TestConfiguration
   
   # Run specific test method
   pytest tests/unit/utils/test_file_utils.py::TestFileUtils::test_split_path_file_extension_basic

**Makefile Integration**:

The project includes Makefile targets for common testing tasks:

.. code-block:: bash

   # Run tests with make
   make test
   
   # Run unit tests only
   make test-unit
   
   # Run tests with coverage
   make test-coverage
   
   # Run linting
   make lint
   
   # Clean test artifacts
   make clean-test

Test Fixtures
-------------

**Global Fixtures (conftest.py)**:

The testing framework provides several global fixtures:

.. code-block:: python

   import pytest
   from pathlib import Path
   from unittest.mock import Mock, MagicMock
   
   @pytest.fixture
   def sample_apk_path():
       """Path to a sample APK file for testing"""
       return "tests/fixtures/sample_apks/test_app.apk"
   
   @pytest.fixture
   def mock_androguard_obj():
       """Mock androguard object with common methods"""
       mock = MagicMock()
       mock.get_package.return_value = "com.example.test"
       mock.get_permissions.return_value = ["android.permission.INTERNET"]
       mock.get_activities.return_value = ["MainActivity"]
       mock.get_libraries.return_value = ["libtest.so"]
       mock.is_valid_apk.return_value = True
       return mock
   
   @pytest.fixture
   def mock_analysis_context():
       """Mock analysis context for testing"""
       from dexray_insight.core.base_classes import AnalysisContext
       
       context = AnalysisContext()
       context.apk_path = "/path/to/test.apk"
       context.module_results = {}
       context.shared_data = {}
       return context
   
   @pytest.fixture
   def test_configuration():
       """Test configuration dictionary"""
       return {
           'analysis': {
               'parallel_execution': {'enabled': True, 'max_workers': 2},
               'timeout': {'module_timeout': 60, 'tool_timeout': 120}
           },
           'modules': {
               'string_analysis': {'enabled': True},
               'permission_analysis': {'enabled': True}
           },
           'logging': {'level': 'DEBUG'}
       }

**Parametrized Fixtures**:

.. code-block:: python

   @pytest.fixture(params=[
       "simple_app.apk",
       "complex_app.apk", 
       "native_app.apk"
   ])
   def various_apk_paths(request):
       """Fixture providing different APK files"""
       return f"tests/fixtures/sample_apks/{request.param}"
   
   @pytest.fixture(params=[
       ('DEBUG', True),
       ('INFO', True), 
       ('WARNING', False),
       ('ERROR', False)
   ])
   def logging_config(request):
       """Fixture providing different logging configurations"""
       level, verbose = request.param
       return {'level': level, 'verbose': verbose}

Synthetic APK Generation
-----------------------

**APK Builder Utility**:

The testing framework includes a synthetic APK builder for creating test APKs:

.. code-block:: python

   from tests.utils.apk_builder import SyntheticApkBuilder
   
   # Create basic APK
   builder = SyntheticApkBuilder()
   apk_path = builder.build_apk(
       package_name="com.test.synthetic",
       version_name="1.0.0",
       framework="Native"
   )
   
   # Create APK with specific features
   apk_path = builder.build_apk(
       package_name="com.test.flutter",
       framework="Flutter",
       permissions=["android.permission.CAMERA", "android.permission.INTERNET"],
       activities=["MainActivity", "SettingsActivity"],
       native_libraries=["libflutter.so", "libapp.so"]
   )

**Framework-Specific APKs**:

.. code-block:: python

   @pytest.fixture
   def flutter_apk():
       """Generate Flutter-based synthetic APK"""
       builder = SyntheticApkBuilder()
       return builder.build_flutter_apk(
           package_name="com.test.flutter",
           include_native_libs=True
       )
   
   @pytest.fixture  
   def react_native_apk():
       """Generate React Native synthetic APK"""
       builder = SyntheticApkBuilder()
       return builder.build_react_native_apk(
           package_name="com.test.reactnative",
           include_hermes=True
       )
   
   @pytest.fixture
   def xamarin_apk():
       """Generate Xamarin synthetic APK"""
       builder = SyntheticApkBuilder()
       return builder.build_xamarin_apk(
           package_name="com.test.xamarin",
           include_mono_runtime=True
       )

Test Data Management
-------------------

**Sample APK Files**:

The test suite includes sample APK files for different scenarios:

.. code-block:: text

   tests/fixtures/sample_apks/
   ├── minimal_app.apk          # Minimal APK with basic components
   ├── permission_heavy.apk     # APK with many permissions
   ├── native_libraries.apk     # APK with multiple .so files
   ├── flutter_app.apk          # Flutter framework APK
   ├── react_native_app.apk     # React Native framework APK
   └── malformed.apk            # Intentionally malformed APK

**Test Data Fixtures**:

.. code-block:: python

   @pytest.fixture
   def sample_string_data():
       """Sample string analysis data"""
       return {
           'urls': [
               'https://api.example.com',
               'http://tracking.com/collect'
           ],
           'ip_addresses': ['192.168.1.1', '8.8.8.8'],
           'email_addresses': ['contact@example.com'],
           'domains': ['api.example.com', 'cdn.example.com'],
           'base64_strings': ['dGVzdCBzdHJpbmc=']
       }
   
   @pytest.fixture
   def sample_permission_data():
       """Sample permission analysis data"""
       return [
           'android.permission.INTERNET',
           'android.permission.CAMERA', 
           'android.permission.ACCESS_FINE_LOCATION',
           'com.example.CUSTOM_PERMISSION'
       ]

Mocking Strategies
-----------------

**External Tool Mocking**:

Mock external tools to avoid dependencies in unit tests:

.. code-block:: python

   @pytest.fixture
   def mock_apktool():
       """Mock apktool execution"""
       with patch('subprocess.run') as mock_run:
           mock_run.return_value = Mock(
               returncode=0,
               stdout="APKTool analysis complete",
               stderr=""
           )
           yield mock_run
   
   @pytest.fixture
   def mock_r2pipe():
       """Mock radare2 pipe connection"""
       with patch('r2pipe.open') as mock_open:
           mock_r2 = Mock()
           mock_r2.cmd.return_value = "analysis result"
           mock_r2.cmdj.return_value = {"analysis": "data"}
           mock_open.return_value = mock_r2
           yield mock_r2

**API Mocking**:

Mock external API calls for signature detection:

.. code-block:: python

   @pytest.fixture
   def mock_virustotal_api():
       """Mock VirusTotal API responses"""
       responses = {
           'scan': {
               'response_code': 1,
               'scan_id': 'test_scan_id'
           },
           'report': {
               'response_code': 1,
               'positives': 3,
               'total': 70,
               'scans': {
                   'Avira': {'detected': True, 'result': 'Android.Malware'},
                   'Kaspersky': {'detected': True, 'result': 'Trojan.Android'},
                   'McAfee': {'detected': False, 'result': None}
               }
           }
       }
       
       with patch('requests.get') as mock_get, \
            patch('requests.post') as mock_post:
           
           mock_get.return_value.json.return_value = responses['report']
           mock_post.return_value.json.return_value = responses['scan']
           
           yield {'get': mock_get, 'post': mock_post}

Test Assertions and Helpers
---------------------------

**Custom Assertions**:

.. code-block:: python

   def assert_valid_analysis_result(result):
       """Assert that analysis result has valid structure"""
       assert hasattr(result, 'module_name')
       assert hasattr(result, 'status')
       assert hasattr(result, 'execution_time')
       assert result.execution_time >= 0
       
       if result.status == AnalysisStatus.FAILURE:
           assert hasattr(result, 'error_message')
           assert result.error_message is not None
   
   def assert_apk_metadata_complete(metadata):
       """Assert APK metadata is complete"""
       required_fields = [
           'package_name', 'version_name', 'version_code',
           'permissions', 'activities'
       ]
       
       for field in required_fields:
           assert field in metadata
           assert metadata[field] is not None
   
   def assert_no_security_issues(security_result):
       """Assert no critical security issues found"""
       if security_result.hardcoded_secrets:
           critical_secrets = [s for s in security_result.hardcoded_secrets 
                             if s['severity'] == 'CRITICAL']
           assert len(critical_secrets) == 0, f"Critical secrets found: {critical_secrets}"

**Test Helpers**:

.. code-block:: python

   def create_temporary_apk(content: bytes) -> str:
       """Create temporary APK file for testing"""
       import tempfile
       
       with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
           f.write(content)
           return f.name
   
   def cleanup_temporary_files(file_paths: List[str]):
       """Clean up temporary test files"""
       import os
       
       for file_path in file_paths:
           try:
               if os.path.exists(file_path):
                   os.unlink(file_path)
           except Exception:
               pass  # Ignore cleanup errors in tests

Performance Testing
------------------

**Timing Tests**:

.. code-block:: python

   import time
   import pytest
   
   @pytest.mark.slow
   def test_analysis_performance(sample_apk_path):
       """Test analysis performance requirements"""
       start_time = time.time()
       
       # Perform analysis
       results = analyze_apk(sample_apk_path)
       
       execution_time = time.time() - start_time
       
       # Assert performance requirements
       assert execution_time < 120, f"Analysis too slow: {execution_time}s"
       assert results is not None
   
   def test_memory_usage():
       """Test memory usage stays within limits"""
       import psutil
       import gc
       
       process = psutil.Process()
       initial_memory = process.memory_info().rss
       
       # Perform memory-intensive operation
       large_analysis_operation()
       
       gc.collect()  # Force garbage collection
       final_memory = process.memory_info().rss
       memory_increase = (final_memory - initial_memory) / 1024 / 1024  # MB
       
       assert memory_increase < 500, f"Excessive memory usage: {memory_increase}MB"

**Concurrency Tests**:

.. code-block:: python

   import threading
   import pytest
   
   def test_parallel_analysis():
       """Test parallel analysis execution"""
       apk_paths = [
           "tests/fixtures/sample_apks/app1.apk",
           "tests/fixtures/sample_apks/app2.apk",
           "tests/fixtures/sample_apks/app3.apk"
       ]
       
       results = []
       threads = []
       
       def analyze_wrapper(apk_path):
           result = analyze_apk(apk_path)
           results.append(result)
       
       # Start parallel analysis
       for apk_path in apk_paths:
           thread = threading.Thread(target=analyze_wrapper, args=(apk_path,))
           thread.start()
           threads.append(thread)
       
       # Wait for completion
       for thread in threads:
           thread.join(timeout=60)  # 60 second timeout
       
       # Verify results
       assert len(results) == len(apk_paths)
       for result in results:
           assert_valid_analysis_result(result)

Error Handling Tests
-------------------

**Exception Testing**:

.. code-block:: python

   def test_invalid_apk_handling():
       """Test handling of invalid APK files"""
       with pytest.raises(ValueError, match="Invalid APK file"):
           analyze_apk("nonexistent.apk")
   
   def test_corrupted_apk_handling():
       """Test handling of corrupted APK files"""
       corrupted_apk = create_temporary_apk(b"invalid apk content")
       
       try:
           result = analyze_apk(corrupted_apk)
           # Should not raise exception, but return failure result
           assert result.status == AnalysisStatus.FAILURE
           assert "corrupted" in result.error_message.lower()
       finally:
           cleanup_temporary_files([corrupted_apk])
   
   def test_timeout_handling():
       """Test module timeout handling"""
       # Mock a module that takes too long
       with patch('time.sleep', side_effect=lambda x: time.sleep(0.1)):  # Speed up test
           with patch('module.analyze', side_effect=lambda: time.sleep(10)):  # Simulate long operation
               result = analyze_apk_with_timeout("test.apk", timeout=1)
               assert result.status == AnalysisStatus.TIMEOUT

Test Coverage
-------------

**Coverage Configuration**:

.. code-block:: ini

   # .coveragerc
   [run]
   source = src/dexray_insight
   omit = 
       */tests/*
       */venv/*
       */env/*
       */__pycache__/*
   
   [report]
   exclude_lines =
       pragma: no cover
       def __repr__
       if self.debug:
       if settings.DEBUG
       raise AssertionError
       raise NotImplementedError
       if 0:
       if __name__ == .__main__.:

**Coverage Goals**:

The project aims for:

* **Unit Tests**: 90%+ coverage for core utilities and base classes
* **Integration Tests**: 80%+ coverage for module interactions  
* **Overall Coverage**: 85%+ across the entire codebase

**Coverage Commands**:

.. code-block:: bash

   # Generate coverage report
   pytest --cov=src/dexray_insight --cov-report=html --cov-report=term
   
   # View detailed coverage report
   coverage report --show-missing
   
   # Generate HTML coverage report
   coverage html
   open htmlcov/index.html

Continuous Integration
---------------------

**GitHub Actions Integration**:

The testing framework integrates with GitHub Actions for automated testing:

.. code-block:: yaml

   # .github/workflows/test.yml
   name: Tests
   
   on: [push, pull_request]
   
   jobs:
     test:
       runs-on: ubuntu-latest
       strategy:
         matrix:
           python-version: [3.8, 3.9, '3.10', 3.11]
       
       steps:
       - uses: actions/checkout@v3
       - name: Set up Python ${{ matrix.python-version }}
         uses: actions/setup-python@v3
         with:
           python-version: ${{ matrix.python-version }}
       
       - name: Install dependencies
         run: |
           python -m pip install --upgrade pip
           pip install -e .[test]
       
       - name: Run tests
         run: |
           pytest --cov=src/dexray_insight --cov-report=xml
       
       - name: Upload coverage
         uses: codecov/codecov-action@v3

**Test Environment Setup**:

.. code-block:: bash

   # Set up test environment
   python -m venv test-env
   source test-env/bin/activate  # On Windows: test-env\Scripts\activate
   
   # Install test dependencies
   pip install -e .[test]
   
   # Install additional test tools
   pip install pytest-xdist pytest-mock pytest-cov

Best Practices
--------------

**Test Organization**:

1. **One test file per module** - Mirror the source code structure
2. **Descriptive test names** - Clearly indicate what is being tested
3. **Arrange-Act-Assert pattern** - Structure tests clearly
4. **Independent tests** - Tests should not depend on each other
5. **Deterministic tests** - Tests should produce consistent results

**Test Writing Guidelines**:

.. code-block:: python

   def test_should_detect_flutter_framework_when_flutter_libraries_present():
       """Test that Flutter framework is detected when Flutter-specific libraries are present"""
       # Arrange
       native_libraries = ['libflutter.so', 'libapp.so', 'libtest.so']
       package_name = 'com.example.flutter'
       classes = []
       
       # Act
       detected_framework = detect_framework(package_name, native_libraries, classes)
       
       # Assert
       assert detected_framework == 'Flutter'

**Mock Usage Guidelines**:

1. **Mock external dependencies** - Don't test third-party code
2. **Mock expensive operations** - File I/O, network calls, etc.
3. **Mock non-deterministic behavior** - Random values, timestamps
4. **Verify mock interactions** - Ensure mocks are called correctly
5. **Reset mocks between tests** - Avoid test interference

The testing framework provides a solid foundation for ensuring code quality and reliability in Dexray Insight. It enables confident refactoring, catches regressions early, and serves as documentation for expected behavior.