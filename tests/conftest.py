#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shared test fixtures and configuration for Dexray Insight tests
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from typing import Dict, Any, List

from .utils.apk_builder import SyntheticAPKBuilder


def pytest_configure(config):
    """Configure pytest with custom markers"""
    # Original test markers
    config.addinivalue_line("markers", "unit: Fast unit tests (< 1s)")
    config.addinivalue_line("markers", "integration: Medium integration tests (1-10s)")
    config.addinivalue_line("markers", "e2e: Slow end-to-end tests (10s+)")
    config.addinivalue_line("markers", "slow: Tests that take more than 10 seconds")
    config.addinivalue_line("markers", "benchmark: Performance benchmark tests")
    config.addinivalue_line("markers", "regression: Tests for known bug scenarios")
    config.addinivalue_line("markers", "refactored: Tests for newly refactored functions")
    config.addinivalue_line("markers", "performance: Performance and benchmarking tests")
    config.addinivalue_line("markers", "security: Security-focused tests")
    
    # Real APK testing markers
    config.addinivalue_line("markers", "real_apk: Tests that use real APK samples from example_samples/")
    config.addinivalue_line("markers", "ci_safe: Tests safe for CI/GitHub Actions (uses only exampleapp-release.apk)")
    config.addinivalue_line("markers", "local_dev: Tests for local development environment (may use all samples)")
    config.addinivalue_line("markers", "malware_sample: Tests that use malware samples (local development only)")
    config.addinivalue_line("markers", "real_apk_regression: Regression tests using real APK samples")
    config.addinivalue_line("markers", "real_apk_performance: Performance tests with real APKs")


# ========================
# Configuration Fixtures
# ========================

@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Standard test configuration with safe defaults"""
    return {
        'external_tools': {
            'apktool_enabled': True,
            'apktool_jar': '/opt/homebrew/Cellar/apktool/2.12.0/libexec/apktool_2.12.0.jar',
            'jadx_enabled': False,  # Disabled for faster tests
            'java_home': None,
        },
        'analysis': {
            'parallel_execution': False,  # Deterministic tests
            'timeout_seconds': 30,
            'max_workers': 1,
        },
        'api_keys': {
            'virustotal': 'test_vt_key_12345',
            'koodous': 'test_koodous_key_12345',
            'triage': 'test_triage_key_12345',
        },
        'modules': {
            'apk_overview': {'enabled': True, 'priority': 1},
            'permission_analysis': {'enabled': True, 'priority': 2},
            'string_analysis': {'enabled': True, 'priority': 3},
            'manifest_analysis': {'enabled': True, 'priority': 4},
        },
        'output': {
            'format': 'json',
            'pretty_print': True,
            'include_debug_info': False,
        }
    }


@pytest.fixture
def temp_analysis_dir():
    """Temporary directory for analysis outputs"""
    with tempfile.TemporaryDirectory(prefix="dexray_test_") as temp_dir:
        yield Path(temp_dir)


# ========================
# APK Fixtures
# ========================

@pytest.fixture(scope="session")
def test_apks_dir(tmp_path_factory):
    """
    Create synthetic test APKs once per test session
    This is expensive so we only do it once
    """
    apk_dir = tmp_path_factory.mktemp("test_apks")
    builder = SyntheticAPKBuilder()
    
    # Create various test APKs with known characteristics
    test_apks = [
        {
            'name': 'minimal_native.apk',
            'type': 'native',
            'package': 'com.test.minimal',
            'native_libs': ['libtest.so', 'libcrypto.so'],
            'permissions': ['android.permission.INTERNET'],
            'activities': ['com.test.minimal.MainActivity'],
            'target_sdk': 30,
        },
        {
            'name': 'flutter_sample.apk',
            'type': 'flutter',
            'package': 'com.test.flutter',
            'native_libs': ['libflutter.so', 'libapp.so'],
            'permissions': ['android.permission.INTERNET', 'android.permission.CAMERA'],
            'flutter_assets': True,
            'target_sdk': 33,
        },
        {
            'name': 'react_native_sample.apk',
            'type': 'react_native',
            'package': 'com.test.reactnative',
            'native_libs': ['libfbjni.so', 'libreactnativejni.so'],
            'permissions': ['android.permission.INTERNET'],
            'js_bundle': True,
            'target_sdk': 31,
        },
        {
            'name': 'xamarin_sample.apk',
            'type': 'xamarin',
            'package': 'com.test.xamarin',
            'native_libs': ['libmonodroid.so', 'libmonosgen.so'],
            'permissions': ['android.permission.WRITE_EXTERNAL_STORAGE'],
            'dotnet_assemblies': ['Mono.Android.dll', 'mscorlib.dll'],
            'target_sdk': 29,
        },
        {
            'name': 'malformed_manifest.apk',
            'type': 'malformed',
            'package': 'com.test.malformed',
            'malformed_manifest': True,
            'permissions': [],
            'target_sdk': 28,
        }
    ]
    
    for apk_spec in test_apks:
        apk_path = apk_dir / apk_spec['name']
        builder.create_apk(apk_path, apk_spec)
    
    return apk_dir


@pytest.fixture
def minimal_native_apk(test_apks_dir):
    """Path to minimal native APK for testing"""
    return test_apks_dir / "minimal_native.apk"


@pytest.fixture
def flutter_sample_apk(test_apks_dir):
    """Path to Flutter sample APK for testing"""
    return test_apks_dir / "flutter_sample.apk"


@pytest.fixture
def react_native_sample_apk(test_apks_dir):
    """Path to React Native sample APK for testing"""
    return test_apks_dir / "react_native_sample.apk"


@pytest.fixture
def malformed_manifest_apk(test_apks_dir):
    """Path to malformed manifest APK for testing edge cases"""
    return test_apks_dir / "malformed_manifest.apk"


# ========================
# Mock Fixtures
# ========================

@pytest.fixture
def mock_androguard_apk():
    """Mock androguard APK object with realistic data"""
    mock = MagicMock()
    mock.get_package.return_value = "com.test.app"
    mock.get_app_name.return_value = "Test Application"
    mock.get_main_activity.return_value = "com.test.app.MainActivity"
    mock.get_target_sdk_version.return_value = 30
    mock.get_min_sdk_version.return_value = 21
    mock.get_max_sdk_version.return_value = None
    mock.get_androidversion_name.return_value = "1.0.0"
    mock.get_androidversion_code.return_value = 1
    
    mock.get_activities.return_value = [
        "com.test.app.MainActivity",
        "com.test.app.SettingsActivity"
    ]
    mock.get_services.return_value = ["com.test.app.BackgroundService"]
    mock.get_receivers.return_value = ["com.test.app.BootReceiver"]
    mock.get_providers.return_value = []
    
    mock.get_permissions.return_value = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE"
    ]
    mock.get_declared_permissions.return_value = []
    
    mock.get_libraries.return_value = ["libtest.so", "libcrypto.so"]
    mock.get_files.return_value = [
        "AndroidManifest.xml",
        "classes.dex",
        "lib/arm64-v8a/libtest.so",
        "lib/arm64-v8a/libcrypto.so",
        "lib/armeabi-v7a/libtest.so",
        "lib/armeabi-v7a/libcrypto.so",
        "res/layout/activity_main.xml",
        "resources.arsc"
    ]
    
    # File hashes
    mock.file_md5 = "a1b2c3d4e5f6789012345678901234567890"
    mock.file_sha1 = "1234567890abcdef1234567890abcdef12345678"
    mock.file_sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    
    # Certificate info
    mock.is_signed_v1.return_value = True
    mock.is_signed_v2.return_value = False
    mock.get_signature_names.return_value = ["CERT.RSA"]
    mock.get_certificate.return_value = MagicMock()
    
    return mock


@pytest.fixture
def mock_external_tools():
    """Mock all external tool executions"""
    with patch('subprocess.run') as mock_run:
        # Default successful response
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Tool execution successful"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        yield mock_run


@pytest.fixture
def mock_api_responses():
    """Mock external API responses"""
    responses_data = {
        'virustotal': {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 0,
                        'suspicious': 0,
                        'undetected': 45,
                        'harmless': 0
                    }
                }
            }
        },
        'koodous': {
            'detected': False,
            'rating': 0
        }
    }
    return responses_data


# ========================
# Analysis Context Fixtures
# ========================

@pytest.fixture
def mock_analysis_context():
    """Mock analysis context for module testing"""
    from src.dexray_insight.core.base_classes import AnalysisContext
    
    context = MagicMock(spec=AnalysisContext)
    context.apk_path = "/path/to/test.apk"
    context.temp_dir = Path("/tmp/test_analysis")
    context.config = {}
    context.shared_data = {}
    context.logger = MagicMock()
    
    return context


# ========================
# Analysis Engine Fixtures (for TDD refactoring)
# ========================

@pytest.fixture
def analysis_engine_config():
    """Create a test configuration for AnalysisEngine"""
    from dexray_insight.core.configuration import Configuration
    return Configuration()

@pytest.fixture
def analysis_engine_logger():
    """Create a mock logger for AnalysisEngine testing"""
    return MagicMock()

@pytest.fixture
def analysis_engine(analysis_engine_config):
    """Create an AnalysisEngine instance for testing"""
    from dexray_insight.core.analysis_engine import AnalysisEngine
    return AnalysisEngine(analysis_engine_config)

@pytest.fixture
def valid_apk_path():
    """Create a temporary valid APK path for testing"""
    import os
    with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp:
        tmp.write(b'PK\x03\x04')  # Minimal ZIP header
        yield tmp.name
    if os.path.exists(tmp.name):
        os.unlink(tmp.name)

@pytest.fixture
def mock_temporal_manager():
    """Create a mock temporal directory manager"""
    mock = MagicMock()
    mock.create_temporal_directory.return_value = MagicMock()
    mock.check_tool_availability.return_value = True
    return mock


# ========================
# Expected Results Fixtures
# ========================

@pytest.fixture
def expected_minimal_native_result():
    """Expected analysis result for minimal native APK"""
    return {
        'apk_overview': {
            'general_info': {
                'package_name': 'com.test.minimal',
                'app_name': 'Test Minimal App',
                'target_sdk': 30,
                'min_sdk': 21
            },
            'native_libs': ['libtest.so', 'libcrypto.so'],
            'is_cross_platform': False,
            'cross_platform_framework': 'Native Android (Java/Kotlin) or Unknown Framework'
        },
        'permissions': {
            'permissions': ['android.permission.INTERNET'],
            'critical_permissions': ['android.permission.INTERNET']
        }
    }


# ========================
# Test Utilities
# ========================

@pytest.fixture
def assert_apk_structure():
    """Utility fixture for validating APK analysis results"""
    def _assert_structure(result: Dict[str, Any], expected_modules: List[str]):
        """Assert that analysis result has expected structure"""
        assert isinstance(result, dict)
        assert 'analysis_metadata' in result
        assert 'modules' in result
        
        for module_name in expected_modules:
            assert module_name in result['modules']
            module_result = result['modules'][module_name]
            assert 'status' in module_result
            assert 'execution_time' in module_result
            
        return True
    
    return _assert_structure


@pytest.fixture
def load_test_data():
    """Utility to load test data files"""
    def _load_data(filename: str) -> Dict[str, Any]:
        """Load JSON test data from fixtures directory"""
        fixtures_dir = Path(__file__).parent / "fixtures"
        file_path = fixtures_dir / filename
        
        with open(file_path, 'r') as f:
            return json.load(f)
    
    return _load_data