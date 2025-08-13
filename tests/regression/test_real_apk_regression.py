#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Real APK Regression Tests

Regression tests using real APK samples to ensure refactored code maintains
the same functionality and produces consistent results. These tests help
prevent regressions after major code changes and refactoring.

Tests covered:
- Baseline result comparison for refactored modules
- Performance regression detection
- Output format consistency validation
- Security assessment result stability
- Module interaction regression testing
- Error handling consistency
"""

import pytest
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from unittest.mock import patch

from tests.fixtures.real_apk_fixtures import (
    ci_safe_apk_path, available_sample_apks, is_ci_environment,
    real_apk_test_config, cached_baseline_results, save_baseline_results,
    mock_external_apis, TEST_RESULTS_CACHE_DIR
)

# Import analysis components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.configuration import Configuration

@dataclass
class RegressionTestResult:
    """Result of a regression test comparison"""
    test_name: str
    passed: bool
    baseline_exists: bool
    current_result_hash: str
    baseline_result_hash: Optional[str] = None
    differences: List[str] = None
    performance_delta: Optional[float] = None
    notes: str = ""

class RegressionAnalyzer:
    """Analyzes results for regression testing"""
    
    @staticmethod
    def normalize_result_for_comparison(result_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize result dictionary for comparison by removing volatile fields.
        Removes timestamps, execution times, and other non-deterministic data.
        """
        normalized = result_dict.copy()
        
        # Remove volatile metadata
        if 'metadata' in normalized:
            metadata = normalized['metadata'].copy()
            # Keep structure but remove time-sensitive data
            volatile_fields = [
                'analysis_timestamp', 'analysis_duration', 'execution_time',
                'start_time', 'end_time', 'timestamp'
            ]
            for field in volatile_fields:
                metadata.pop(field, None)
            normalized['metadata'] = metadata
        
        # Normalize module-specific volatile data
        modules_to_normalize = [
            'apk_overview', 'library_detection', 'tracker_analysis',
            'security_assessment', 'string_analysis'
        ]
        
        for module in modules_to_normalize:
            if module in normalized:
                normalized[module] = RegressionAnalyzer._normalize_module_result(
                    normalized[module], module
                )
        
        return normalized
    
    @staticmethod
    def _normalize_module_result(module_result: Dict[str, Any], module_name: str) -> Dict[str, Any]:
        """Normalize module-specific results"""
        if not isinstance(module_result, dict):
            return module_result
        
        normalized = module_result.copy()
        
        # Remove execution time fields
        time_fields = ['execution_time', 'analysis_time', 'duration']
        for field in time_fields:
            normalized.pop(field, None)
        
        # Module-specific normalizations
        if module_name == 'library_detection':
            # Normalize library detection results
            if 'detected_libraries' in normalized:
                libs = normalized['detected_libraries']
                if isinstance(libs, list):
                    # Sort libraries by name for consistent comparison
                    normalized['detected_libraries'] = sorted(
                        libs, key=lambda x: x.get('name', '') if isinstance(x, dict) else str(x)
                    )
        
        elif module_name == 'tracker_analysis':
            # Normalize tracker analysis results
            if 'detected_trackers' in normalized:
                trackers = normalized['detected_trackers']
                if isinstance(trackers, list):
                    # Sort trackers by name for consistent comparison
                    normalized['detected_trackers'] = sorted(
                        trackers, key=lambda x: x.get('name', '') if isinstance(x, dict) else str(x)
                    )
        
        elif module_name == 'security_assessment':
            # Normalize security findings (order might vary)
            if 'findings' in normalized:
                findings = normalized['findings']
                if isinstance(findings, list):
                    # Sort findings by category and title for consistency
                    normalized['findings'] = sorted(
                        findings, 
                        key=lambda x: (x.get('category', ''), x.get('title', '')) if isinstance(x, dict) else str(x)
                    )
        
        return normalized
    
    @staticmethod
    def calculate_result_hash(result_dict: Dict[str, Any]) -> str:
        """Calculate deterministic hash of normalized results"""
        normalized = RegressionAnalyzer.normalize_result_for_comparison(result_dict)
        
        # Convert to deterministic JSON string
        json_str = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
        
        # Calculate hash
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    @staticmethod
    def find_differences(current: Dict[str, Any], baseline: Dict[str, Any]) -> List[str]:
        """Find specific differences between current and baseline results"""
        differences = []
        
        # Normalize both for comparison
        norm_current = RegressionAnalyzer.normalize_result_for_comparison(current)
        norm_baseline = RegressionAnalyzer.normalize_result_for_comparison(baseline)
        
        # Compare top-level keys
        current_keys = set(norm_current.keys())
        baseline_keys = set(norm_baseline.keys())
        
        if current_keys != baseline_keys:
            missing_keys = baseline_keys - current_keys
            new_keys = current_keys - baseline_keys
            
            if missing_keys:
                differences.append(f"Missing keys: {sorted(missing_keys)}")
            if new_keys:
                differences.append(f"New keys: {sorted(new_keys)}")
        
        # Compare common keys
        common_keys = current_keys & baseline_keys
        for key in common_keys:
            key_diffs = RegressionAnalyzer._compare_values(
                norm_current[key], norm_baseline[key], f"root.{key}"
            )
            differences.extend(key_diffs)
        
        return differences
    
    @staticmethod
    def _compare_values(current: Any, baseline: Any, path: str) -> List[str]:
        """Recursively compare values and report differences"""
        differences = []
        
        if type(current) != type(baseline):
            differences.append(f"{path}: Type changed from {type(baseline).__name__} to {type(current).__name__}")
            return differences
        
        if isinstance(current, dict) and isinstance(baseline, dict):
            # Compare dictionaries
            current_keys = set(current.keys())
            baseline_keys = set(baseline.keys())
            
            if current_keys != baseline_keys:
                missing = baseline_keys - current_keys
                new = current_keys - baseline_keys
                if missing:
                    differences.append(f"{path}: Missing keys {sorted(missing)}")
                if new:
                    differences.append(f"{path}: New keys {sorted(new)}")
            
            # Compare common keys
            for key in current_keys & baseline_keys:
                sub_diffs = RegressionAnalyzer._compare_values(
                    current[key], baseline[key], f"{path}.{key}"
                )
                differences.extend(sub_diffs)
        
        elif isinstance(current, list) and isinstance(baseline, list):
            # Compare lists
            if len(current) != len(baseline):
                differences.append(f"{path}: List length changed from {len(baseline)} to {len(current)}")
            
            # Compare elements (up to minimum length)
            min_len = min(len(current), len(baseline))
            for i in range(min_len):
                elem_diffs = RegressionAnalyzer._compare_values(
                    current[i], baseline[i], f"{path}[{i}]"
                )
                differences.extend(elem_diffs)
        
        else:
            # Compare primitive values
            if current != baseline:
                differences.append(f"{path}: Value changed from {baseline} to {current}")
        
        return differences

@pytest.mark.real_apk
@pytest.mark.regression
class TestRealAPKRegression:
    """Regression tests using real APK samples"""
    
    def test_ci_safe_apk_baseline_regression(self, ci_safe_apk_path, real_apk_test_config,
                                           cached_baseline_results, mock_external_apis):
        """
        Test regression against cached baseline for CI-safe APK.
        This is the primary regression test ensuring refactored code maintains functionality.
        """
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        # Perform current analysis
        start_time = time.time()
        current_results = engine.analyze_apk(str(ci_safe_apk_path))
        current_duration = time.time() - start_time
        
        assert current_results is not None, "Current analysis should succeed"
        current_dict = current_results.to_dict()
        
        # Calculate current result hash
        current_hash = RegressionAnalyzer.calculate_result_hash(current_dict)
        
        if cached_baseline_results is None:
            # No baseline exists - save current as baseline
            save_baseline_results("exampleapp-release.apk", current_dict)
            pytest.skip("No baseline available - saved current results as baseline")
        
        # Compare with baseline
        baseline_hash = RegressionAnalyzer.calculate_result_hash(cached_baseline_results)
        
        if current_hash == baseline_hash:
            # Perfect match - no regression
            print(f"✓ No regression detected (hash: {current_hash[:12]}...)")
            return
        
        # Results differ - analyze differences
        differences = RegressionAnalyzer.find_differences(current_dict, cached_baseline_results)
        
        if not differences:
            # Hashes differ but no semantic differences found
            print(f"ℹ Hashes differ but no semantic differences detected")
            print(f"  Current: {current_hash[:12]}...")
            print(f"  Baseline: {baseline_hash[:12]}...")
            return
        
        # Report differences
        print(f"\n⚠ Regression detected in APK analysis:")
        print(f"  Current hash: {current_hash[:12]}...")
        print(f"  Baseline hash: {baseline_hash[:12]}...")
        print(f"  Differences found: {len(differences)}")
        
        for i, diff in enumerate(differences[:10]):  # Show first 10 differences
            print(f"    {i+1}. {diff}")
        
        if len(differences) > 10:
            print(f"    ... and {len(differences) - 10} more differences")
        
        # Decide if regression is acceptable
        acceptable_difference_types = [
            "New keys:",  # New features are acceptable
            "execution_time",  # Performance variations acceptable
            "timestamp"  # Timestamp differences acceptable
        ]
        
        critical_differences = [
            diff for diff in differences
            if not any(acceptable in diff for acceptable in acceptable_difference_types)
        ]
        
        if critical_differences:
            pytest.fail(f"Critical regression detected with {len(critical_differences)} significant differences")
    
    def test_module_specific_regression_library_detection(self, ci_safe_apk_path,
                                                        real_apk_test_config, mock_external_apis):
        """
        Test regression specifically for library detection module.
        Validates that library detection results remain consistent.
        """
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        results = engine.analyze_apk(str(ci_safe_apk_path))
        assert results is not None, "Analysis should succeed"
        
        results_dict = results.to_dict()
        lib_detection = results_dict.get('library_detection', {})
        
        # Check for regression in library detection structure
        required_fields = ['detected_libraries']
        for field in required_fields:
            assert field in lib_detection, f"Library detection should contain {field}"
        
        # Validate library detection consistency
        detected_libs = lib_detection.get('detected_libraries', [])
        
        # Handle different result structure formats
        if 'total_libraries' in lib_detection:
            total_count = lib_detection['total_libraries']
            assert len(detected_libs) == total_count, "Library count should match array length"
        else:
            # Alternative structure - count from detected libraries
            total_count = len(detected_libs)
            print(f"Library detection: {total_count} libraries (inferred from detected_libraries length)")
        
        # Cache library detection baseline
        cache_file = TEST_RESULTS_CACHE_DIR / "library_detection_baseline.json"
        
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                baseline_lib_detection = json.load(f)
            
            # Compare library detection results
            current_lib_names = {lib.get('name') for lib in detected_libs if isinstance(lib, dict)}
            baseline_lib_names = {lib.get('name') for lib in baseline_lib_detection.get('detected_libraries', []) if isinstance(lib, dict)}
            
            # Allow for minor variations but check for major regressions
            if baseline_lib_names:
                # Calculate similarity
                intersection = current_lib_names & baseline_lib_names
                union = current_lib_names | baseline_lib_names
                
                if union:
                    similarity = len(intersection) / len(union)
                    
                    print(f"Library detection similarity: {similarity:.2%}")
                    print(f"Current libraries: {len(current_lib_names)}")
                    print(f"Baseline libraries: {len(baseline_lib_names)}")
                    
                    # Assert reasonable similarity (allow for some variation)
                    assert similarity >= 0.8, f"Library detection similarity too low: {similarity:.2%}"
        else:
            # Save current as baseline
            with open(cache_file, 'w') as f:
                json.dump(lib_detection, f, indent=2)
    
    def test_security_assessment_regression(self, ci_safe_apk_path, real_apk_test_config, mock_external_apis):
        """
        Test regression for security assessment functionality.
        Note: exampleapp-release.apk is a clean sample, so we test consistency 
        of the assessment process rather than expecting specific findings.
        """
        # Enable security assessment
        security_config = real_apk_test_config.copy()
        security_config['security']['enable_owasp_assessment'] = True
        
        config = Configuration(config_dict=security_config)
        engine = AnalysisEngine(config)
        
        results = engine.analyze_apk(str(ci_safe_apk_path))
        assert results is not None, "Security analysis should succeed"
        
        results_dict = results.to_dict()
        security_assessment = results_dict.get('security_assessment', {})
        
        # Validate security assessment structure
        expected_fields = ['findings', 'risk_score']
        for field in expected_fields:
            assert field in security_assessment, f"Security assessment should contain {field}"
        
        # For clean APK, validate that assessment runs properly
        current_findings = security_assessment.get('findings', [])
        current_risk_score = security_assessment.get('risk_score', 0)
        
        # Clean APK should have low risk
        assert current_risk_score >= 0, "Risk score should be non-negative"
        assert current_risk_score <= 50, "Clean APK should have low risk score (≤50)"  # Reasonable threshold for clean APK
        
        print(f"Clean APK security assessment - Risk: {current_risk_score}, Findings: {len(current_findings)}")
        
        # Cache security assessment baseline for clean APK
        cache_file = TEST_RESULTS_CACHE_DIR / "security_assessment_clean_apk_baseline.json"
        
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                baseline_security = json.load(f)
            
            baseline_findings = baseline_security.get('findings', [])
            baseline_risk_score = baseline_security.get('risk_score', 0)
            
            # For clean APK, we expect consistent low-risk assessments
            print(f"Baseline security assessment - Risk: {baseline_risk_score}, Findings: {len(baseline_findings)}")
            
            # Risk score should remain consistently low for clean APK
            risk_variance = abs(current_risk_score - baseline_risk_score)
            assert risk_variance <= 10, f"Risk score variance too high for clean APK: {baseline_risk_score} -> {current_risk_score}"
            
            # Finding count should be relatively stable for clean APK
            finding_count_diff = abs(len(current_findings) - len(baseline_findings))
            assert finding_count_diff <= 2, f"Finding count changed significantly for clean APK: {len(baseline_findings)} -> {len(current_findings)}"
            
            # Check that we're not introducing false positives or missing real issues
            if current_findings or baseline_findings:
                print(f"Security findings comparison:")
                print(f"  Current: {[f.get('title', 'Unknown') for f in current_findings if isinstance(f, dict)]}")
                print(f"  Baseline: {[f.get('title', 'Unknown') for f in baseline_findings if isinstance(f, dict)]}")
        else:
            # Save current as baseline for clean APK
            with open(cache_file, 'w') as f:
                json.dump(security_assessment, f, indent=2)
            print(f"Saved clean APK security assessment baseline: {current_risk_score} risk, {len(current_findings)} findings")
    
    @pytest.mark.performance
    def test_performance_regression(self, ci_safe_apk_path, real_apk_test_config, mock_external_apis):
        """
        Test for performance regression with real APK.
        Ensures refactored code doesn't significantly impact performance.
        """
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        # Run multiple iterations for stable performance measurement
        durations = []
        num_iterations = 3
        
        for i in range(num_iterations):
            start_time = time.time()
            results = engine.analyze_apk(str(ci_safe_apk_path))
            end_time = time.time()
            
            assert results is not None, f"Performance test iteration {i+1} should succeed"
            durations.append(end_time - start_time)
        
        # Calculate performance metrics
        avg_duration = sum(durations) / len(durations)
        min_duration = min(durations)
        max_duration = max(durations)
        
        # Load performance baseline
        perf_cache_file = TEST_RESULTS_CACHE_DIR / "performance_baseline.json"
        
        current_perf = {
            'avg_duration': avg_duration,
            'min_duration': min_duration,
            'max_duration': max_duration,
            'apk_size': ci_safe_apk_path.stat().st_size
        }
        
        if perf_cache_file.exists():
            with open(perf_cache_file, 'r') as f:
                baseline_perf = json.load(f)
            
            baseline_avg = baseline_perf.get('avg_duration', 0)
            
            if baseline_avg > 0:
                performance_ratio = avg_duration / baseline_avg
                
                print(f"Performance comparison:")
                print(f"  Current average: {avg_duration:.2f}s")
                print(f"  Baseline average: {baseline_avg:.2f}s")
                print(f"  Performance ratio: {performance_ratio:.2f}x")
                
                # Assert performance hasn't regressed significantly
                max_acceptable_ratio = 1.5  # 50% slower is still acceptable
                assert performance_ratio <= max_acceptable_ratio, \
                    f"Performance regression: {performance_ratio:.2f}x slower than baseline"
                
                # Log performance improvement if any
                if performance_ratio < 0.9:
                    print(f"🚀 Performance improvement: {(1-performance_ratio)*100:.1f}% faster")
        else:
            # Save current performance as baseline
            with open(perf_cache_file, 'w') as f:
                json.dump(current_perf, f, indent=2)
            print(f"Saved performance baseline: {avg_duration:.2f}s average")
    
    @pytest.mark.local_dev
    def test_multiple_apk_regression(self, available_sample_apks, real_apk_test_config, 
                                   is_ci_environment, mock_external_apis):
        """
        Test regression across multiple APK samples (local development only).
        Validates consistency across diverse APK types.
        """
        if is_ci_environment:
            pytest.skip("Multiple APK regression test not run in CI")
        
        if not available_sample_apks:
            pytest.skip("No APK samples available for multiple APK regression test")
        
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        # Test first few APKs to save time
        test_apks = available_sample_apks[:3]
        
        regression_results = []
        
        for apk_path in test_apks:
            try:
                results = engine.analyze_apk(str(apk_path))
                
                if results is not None:
                    results_dict = results.to_dict()
                    result_hash = RegressionAnalyzer.calculate_result_hash(results_dict)
                    
                    regression_result = RegressionTestResult(
                        test_name=f"regression_{apk_path.stem}",
                        passed=True,
                        baseline_exists=False,
                        current_result_hash=result_hash
                    )
                else:
                    regression_result = RegressionTestResult(
                        test_name=f"regression_{apk_path.stem}",
                        passed=False,
                        baseline_exists=False,
                        current_result_hash="",
                        notes="Analysis returned None"
                    )
                
                regression_results.append(regression_result)
                
            except Exception as e:
                regression_result = RegressionTestResult(
                    test_name=f"regression_{apk_path.stem}",
                    passed=False,
                    baseline_exists=False,
                    current_result_hash="",
                    notes=f"Exception: {str(e)}"
                )
                regression_results.append(regression_result)
        
        # Validate regression results
        successful_tests = [r for r in regression_results if r.passed]
        
        print(f"\nMultiple APK Regression Summary:")
        print(f"  Total APKs tested: {len(regression_results)}")
        print(f"  Successful analyses: {len(successful_tests)}")
        print(f"  Failed analyses: {len(regression_results) - len(successful_tests)}")
        
        for result in regression_results:
            status = "✓" if result.passed else "✗"
            print(f"  {status} {result.test_name}")
            if not result.passed and result.notes:
                print(f"    {result.notes}")
        
        # Assert reasonable success rate
        if regression_results:
            success_rate = len(successful_tests) / len(regression_results)
            assert success_rate >= 0.6, f"Multiple APK regression success rate too low: {success_rate:.1%}"

@pytest.mark.real_apk
@pytest.mark.regression
class TestRegressionUtilities:
    """Utility tests for regression testing framework"""
    
    def test_regression_analyzer_normalization(self):
        """Test that regression analyzer properly normalizes results"""
        # Create test result with volatile data
        test_result = {
            'metadata': {
                'analysis_timestamp': '2024-01-01T12:00:00Z',
                'analysis_duration': 45.67,
                'dexray_version': '1.0.0'
            },
            'apk_overview': {
                'package_name': 'com.test.app',
                'app_name': 'Test App'
            },
            'library_detection': {
                'detected_libraries': [
                    {'name': 'LibraryB', 'version': '2.0'},
                    {'name': 'LibraryA', 'version': '1.0'}
                ],
                'execution_time': 12.34
            }
        }
        
        # Normalize result
        normalized = RegressionAnalyzer.normalize_result_for_comparison(test_result)
        
        # Volatile fields should be removed
        assert 'analysis_timestamp' not in normalized['metadata']
        assert 'analysis_duration' not in normalized['metadata']
        assert 'dexray_version' in normalized['metadata']  # Non-volatile should remain
        
        assert 'execution_time' not in normalized['library_detection']
        
        # Libraries should be sorted
        libs = normalized['library_detection']['detected_libraries']
        assert libs[0]['name'] == 'LibraryA'  # Should be sorted alphabetically
        assert libs[1]['name'] == 'LibraryB'
    
    def test_regression_hash_consistency(self):
        """Test that hash calculation is deterministic"""
        test_result = {
            'apk_overview': {'package_name': 'com.test.app'},
            'metadata': {'version': '1.0'}
        }
        
        # Calculate hash multiple times
        hash1 = RegressionAnalyzer.calculate_result_hash(test_result)
        hash2 = RegressionAnalyzer.calculate_result_hash(test_result)
        
        assert hash1 == hash2, "Hash calculation should be deterministic"
        
        # Different data should produce different hashes
        test_result2 = test_result.copy()
        test_result2['apk_overview']['package_name'] = 'com.different.app'
        
        hash3 = RegressionAnalyzer.calculate_result_hash(test_result2)
        assert hash1 != hash3, "Different data should produce different hashes"