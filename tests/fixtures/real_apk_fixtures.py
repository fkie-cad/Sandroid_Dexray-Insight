#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Real APK Testing Fixtures

Provides shared fixtures and utilities for testing with real APK samples.
Handles APK availability checking, baseline result caching, and CI/local environment differences.
"""

import pytest
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from dexray_insight.Utils.file_utils import CustomJSONEncoder

# Test configuration constants
EXAMPLE_SAMPLES_DIR = Path(__file__).parent.parent.parent / "example_samples"
CI_SAFE_APK = "exampleapp-release.apk"  # Only APK used in GitHub Actions
TEST_RESULTS_CACHE_DIR = Path(__file__).parent / "test_results_cache"

# Create cache directory if it doesn't exist
TEST_RESULTS_CACHE_DIR.mkdir(exist_ok=True)

@pytest.fixture(scope="session")
def ci_safe_apk_path():
    """
    Provides path to the CI-safe APK (exampleapp-release.apk).
    This APK is always available and safe for GitHub Actions.
    """
    apk_path = EXAMPLE_SAMPLES_DIR / CI_SAFE_APK
    if not apk_path.exists():
        pytest.skip(f"CI-safe APK not found: {apk_path}")
    return apk_path

@pytest.fixture(scope="session") 
def available_sample_apks():
    """
    Returns list of all available APK samples for local development testing.
    Excludes password-protected archives and provides graceful handling for CI.
    """
    if not EXAMPLE_SAMPLES_DIR.exists():
        return []
    
    apk_files = []
    for apk_file in EXAMPLE_SAMPLES_DIR.glob("*.apk"):
        # Skip if file is too large for CI (>50MB)
        if apk_file.stat().st_size > 50 * 1024 * 1024:
            continue
        apk_files.append(apk_file)
    
    return sorted(apk_files)

@pytest.fixture
def is_ci_environment():
    """Detect if running in CI environment (GitHub Actions)"""
    import os
    return os.getenv('GITHUB_ACTIONS') == 'true'

@pytest.fixture
def real_apk_test_config():
    """
    Provides optimized configuration for real APK testing.
    Balances thoroughness with reasonable execution time.
    """
    return {
        'modules': {
            'apk_overview': {'enabled': True, 'timeout': 60},
            'manifest_analysis': {'enabled': True, 'timeout': 30},
            'permission_analysis': {'enabled': True, 'timeout': 30},
            'string_analysis': {'enabled': True, 'timeout': 120},
            'api_invocation': {'enabled': True, 'timeout': 180},
            'library_detection': {
                'enabled': True, 
                'timeout': 180,
                'enable_heuristic': True,
                'enable_similarity': True,
                'version_analysis': {
                    'enabled': True,
                    'security_analysis_only': False
                }
            },
            'tracker_analysis': {'enabled': True, 'timeout': 60},
            'behaviour_analysis': {'enabled': True, 'timeout': 120}
        },
        'external_tools': {
            'apktool': {'enabled': True, 'timeout': 120},
            'jadx': {'enabled': False},  # Disable for speed in tests
            'apkid': {'enabled': True, 'timeout': 60}
        },
        'security': {
            'enable_owasp_assessment': True,
            'assessments': {
                'injection': {'enabled': True},
                'broken_access_control': {'enabled': True},
                'sensitive_data': {'enabled': True},
                'xml_external_entities': {'enabled': True},
                'broken_authentication': {'enabled': True},
                'security_misconfiguration': {'enabled': True},
                'cross_site_scripting': {'enabled': True},
                'insecure_deserialization': {'enabled': True},
                'components_with_known_vulnerabilities': {'enabled': True},
                'insufficient_logging_monitoring': {'enabled': True}
            }
        },
        'output': {
            'formats': ['json'],
            'include_evidence': True,
            'include_metadata': True
        }
    }

class RealAPKTestValidator:
    """
    Validates analysis results from real APKs to ensure consistency and correctness.
    """
    
    @staticmethod
    def validate_basic_structure(results: Dict[str, Any], strict: bool = True) -> List[str]:
        """Validate that analysis results have expected basic structure
        
        Args:
            results: The analysis results dictionary
            strict: If True, requires all modules. If False, only checks existing modules.
        """
        errors = []
        
        # Check required top-level keys
        required_keys = [
            'apk_overview', 'manifest_analysis', 'permission_analysis',
            'string_analysis', 'library_detection', 'tracker_analysis'
        ]
        
        # In non-strict mode, only warn about missing modules
        missing_modules = []
        for key in required_keys:
            if key not in results:
                if strict:
                    errors.append(f"Missing required key: {key}")
                else:
                    missing_modules.append(key)
        
        if missing_modules and not strict:
            print(f"Warning: Missing modules (may have failed): {missing_modules}")
        
        # Check APK overview structure if present
        if 'apk_overview' in results:
            apk_overview = results['apk_overview']
            required_overview_keys = ['package_name', 'app_name', 'version_name']
            missing_overview = []
            for key in required_overview_keys:
                if key not in apk_overview:
                    if strict:
                        errors.append(f"Missing APK overview key: {key}")
                    else:
                        missing_overview.append(key)
            
            if missing_overview and not strict:
                print(f"Warning: Missing APK overview keys: {missing_overview}")
        
        return errors
    
    @staticmethod
    def validate_performance_metrics(results: Dict[str, Any], max_duration: float = 300.0) -> List[str]:
        """Validate that analysis completed within reasonable time"""
        errors = []
        
        if 'metadata' in results and 'analysis_duration' in results['metadata']:
            duration = results['metadata']['analysis_duration']
            if duration > max_duration:
                errors.append(f"Analysis took too long: {duration:.2f}s > {max_duration}s")
        
        return errors
    
    @staticmethod
    def validate_security_assessment(results: Dict[str, Any]) -> List[str]:
        """Validate security assessment results structure"""
        errors = []
        
        if 'security_assessment' in results:
            security = results['security_assessment']
            
            # Check for OWASP categories
            if 'findings' in security:
                findings = security['findings']
                if not isinstance(findings, list):
                    errors.append("Security findings should be a list")
                
                # Validate finding structure
                for i, finding in enumerate(findings):
                    if not isinstance(finding, dict):
                        errors.append(f"Finding {i} should be a dictionary")
                        continue
                    
                    required_finding_keys = ['category', 'severity', 'title', 'description']
                    for key in required_finding_keys:
                        if key not in finding:
                            errors.append(f"Finding {i} missing key: {key}")
        
        return errors

@pytest.fixture
def apk_test_validator():
    """Provides validator instance for test result validation"""
    return RealAPKTestValidator()

@pytest.fixture
def performance_tracker():
    """
    Tracks performance metrics during real APK analysis.
    Useful for regression testing and optimization.
    """
    class PerformanceTracker:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.metrics = {}
        
        def start(self):
            self.start_time = time.time()
        
        def end(self):
            self.end_time = time.time()
        
        def duration(self) -> float:
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return 0.0
        
        def add_metric(self, name: str, value: Any):
            self.metrics[name] = value
        
        def get_summary(self) -> Dict[str, Any]:
            return {
                'duration': self.duration(),
                'metrics': self.metrics.copy()
            }
    
    return PerformanceTracker()

@pytest.fixture
def cached_baseline_results(ci_safe_apk_path):
    """
    Provides cached baseline results for the CI-safe APK.
    Useful for regression testing to ensure refactored code produces same results.
    """
    cache_file = TEST_RESULTS_CACHE_DIR / f"{CI_SAFE_APK}_baseline.json"
    
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass  # Fall through to return None
    
    return None

def save_baseline_results(apk_name: str, results: Dict[str, Any]):
    """
    Save analysis results as baseline for future regression testing.
    Should be called when we're confident the results are correct.
    """
    cache_file = TEST_RESULTS_CACHE_DIR / f"{apk_name}_baseline.json"
    
    try:
        with open(cache_file, 'w') as f:
            json.dump(results, f, cls=CustomJSONEncoder, indent=2, sort_keys=True)
        logging.info(f"Saved baseline results to {cache_file}")
    except IOError as e:
        logging.warning(f"Failed to save baseline results: {e}")

@pytest.fixture
def mock_external_apis():
    """
    Mock external API calls for consistent testing.
    Real APK tests should focus on internal analysis, not external API responses.
    """
    with patch('requests.get') as mock_get:
        # Mock VirusTotal API response
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 0,
                        'suspicious': 0,
                        'harmless': 1
                    }
                }
            }
        }
        yield mock_get

@pytest.fixture(scope="session")
def apk_analysis_cache():
    """
    Session-scoped cache to avoid re-analyzing the same APK multiple times.
    Significantly speeds up test suite execution.
    """
    return {}

@pytest.fixture
def androguard_obj_factory():
    """
    Factory fixture to create Androguard objects for real APK testing.
    This properly initializes Androguard objects as the main application does.
    """
    def create_androguard_obj(apk_path: Path):
        """Create and return an initialized Androguard object for the given APK"""
        try:
            # Import the androguard utility class
            import sys
            from pathlib import Path
            
            # Add src to path for imports
            project_root = Path(__file__).parent.parent.parent
            sys.path.insert(0, str(project_root / "src"))
            
            from dexray_insight.Utils import androguardObjClass
            
            print(f"Creating Androguard object for: {apk_path}")
            androguard_obj = androguardObjClass.Androguard_Obj(str(apk_path))
            return androguard_obj
        except Exception as e:
            print(f"Failed to create Androguard object: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    return create_androguard_obj

# Pytest markers for real APK tests
pytest_markers = [
    "real_apk: Tests that use real APK samples",
    "ci_safe: Tests safe for CI/GitHub Actions", 
    "local_dev: Tests that require local development environment",
    "malware_sample: Tests that use malware samples (local only)",
    "performance: Performance benchmarking tests",
    "regression: Regression prevention tests"
]