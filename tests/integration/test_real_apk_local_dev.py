#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Local Development Real APK Tests

Advanced integration tests for local development environments that can optionally
test with malware samples and larger APKs. These tests skip gracefully when 
samples are not available (e.g., in CI environments).

Tests covered:
- Malware detection capabilities with known malicious samples
- Edge case handling with various APK types and sizes
- Performance testing with larger samples
- Advanced security assessment validation
- Comprehensive error handling scenarios
"""

import pytest
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

from tests.fixtures.real_apk_fixtures import (
    available_sample_apks, is_ci_environment, real_apk_test_config,
    apk_test_validator, performance_tracker, mock_external_apis
)

# Import analysis components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.configuration import Configuration

@pytest.mark.real_apk
@pytest.mark.local_dev
@pytest.mark.integration
class TestRealAPKLocalDevelopment:
    """Local development tests with optional malware samples"""
    
    def test_skip_in_ci_environment(self, is_ci_environment):
        """Ensure these tests skip in CI environments"""
        if is_ci_environment:
            pytest.skip("Local development tests are not run in CI environment")
    
    def test_all_available_samples_basic_analysis(self, available_sample_apks, 
                                                real_apk_test_config, mock_external_apis):
        """
        Test basic analysis pipeline with all available APK samples.
        Validates that the tool can handle various APK types without crashing.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for testing")
        
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        results_summary = []
        
        for apk_path in available_sample_apks:
            try:
                # Perform analysis
                results = engine.analyze_apk(str(apk_path))
                
                if results is not None:
                    results_dict = results.to_dict()
                    
                    # Collect summary statistics
                    summary = {
                        'apk_name': apk_path.name,
                        'apk_size_mb': apk_path.stat().st_size / (1024 * 1024),
                        'analysis_success': True,
                        'libraries_detected': len(results_dict.get('library_detection', {}).get('detected_libraries', [])),
                        'trackers_detected': len(results_dict.get('tracker_analysis', {}).get('detected_trackers', [])),
                        'security_findings': len(results_dict.get('security_assessment', {}).get('findings', [])),
                        'has_security_assessment': 'security_assessment' in results_dict
                    }
                else:
                    summary = {
                        'apk_name': apk_path.name,
                        'apk_size_mb': apk_path.stat().st_size / (1024 * 1024),
                        'analysis_success': False,
                        'error': 'Analysis returned None'
                    }
                
                results_summary.append(summary)
                
            except Exception as e:
                # Log error but continue with other samples
                summary = {
                    'apk_name': apk_path.name,
                    'apk_size_mb': apk_path.stat().st_size / (1024 * 1024),
                    'analysis_success': False,
                    'error': str(e)
                }
                results_summary.append(summary)
                logging.warning(f"Analysis failed for {apk_path.name}: {e}")
        
        # Validate results
        successful_analyses = [r for r in results_summary if r['analysis_success']]
        assert len(successful_analyses) > 0, "At least one APK should be analyzed successfully"
        
        # Log summary for debugging
        print(f"\nAnalysis Summary:")
        print(f"Total APKs: {len(results_summary)}")
        print(f"Successful: {len(successful_analyses)}")
        print(f"Failed: {len(results_summary) - len(successful_analyses)}")
        
        for result in results_summary:
            status = "✓" if result['analysis_success'] else "✗"
            print(f"  {status} {result['apk_name']} ({result['apk_size_mb']:.1f}MB)")
            if not result['analysis_success']:
                print(f"    Error: {result.get('error', 'Unknown')}")
    
    @pytest.mark.malware_sample
    def test_malware_detection_capabilities(self, available_sample_apks, 
                                          real_apk_test_config, mock_external_apis):
        """
        Test malware detection capabilities with known malicious samples.
        This test focuses on security assessment effectiveness.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for malware testing")
        
        # Identify potential malware samples by name patterns
        malware_indicators = ['malware', 'bianlian', 'trojan', 'virus', 'infected']
        potential_malware = []
        
        for apk_path in available_sample_apks:
            apk_name_lower = apk_path.name.lower()
            if any(indicator in apk_name_lower for indicator in malware_indicators):
                potential_malware.append(apk_path)
        
        if not potential_malware:
            pytest.skip("No potential malware samples identified")
        
        # Enable comprehensive security assessment
        security_config = real_apk_test_config.copy()
        security_config['security']['enable_owasp_assessment'] = True
        
        config = Configuration(config_dict=security_config)
        engine = AnalysisEngine(config)
        
        malware_results = []
        
        for apk_path in potential_malware:
            try:
                results = engine.analyze_apk(str(apk_path))
                
                if results is not None:
                    results_dict = results.to_dict()
                    
                    # Analyze security findings
                    security_assessment = results_dict.get('security_assessment', {})
                    findings = security_assessment.get('findings', [])
                    risk_score = security_assessment.get('risk_score', 0)
                    
                    malware_analysis = {
                        'apk_name': apk_path.name,
                        'security_findings_count': len(findings),
                        'risk_score': risk_score,
                        'high_severity_findings': len([f for f in findings if f.get('severity') == 'HIGH']),
                        'critical_findings': len([f for f in findings if f.get('severity') == 'CRITICAL']),
                        'owasp_categories': list(set(f.get('category', '').split(':')[0] for f in findings if f.get('category')))
                    }
                    
                    malware_results.append(malware_analysis)
                
            except Exception as e:
                logging.warning(f"Malware analysis failed for {apk_path.name}: {e}")
        
        # Validate malware detection effectiveness
        if malware_results:
            # At least one malware sample should trigger security findings
            samples_with_findings = [r for r in malware_results if r['security_findings_count'] > 0]
            
            print(f"\nMalware Detection Results:")
            for result in malware_results:
                print(f"  {result['apk_name']}:")
                print(f"    Findings: {result['security_findings_count']}")
                print(f"    Risk Score: {result['risk_score']}")
                print(f"    High/Critical: {result['high_severity_findings']}/{result['critical_findings']}")
                print(f"    OWASP Categories: {result['owasp_categories']}")
            
            # Assert that malware detection is working
            assert len(samples_with_findings) > 0, \
                "At least one malware sample should trigger security findings"
    
    @pytest.mark.performance
    def test_performance_with_various_apk_sizes(self, available_sample_apks,
                                               real_apk_test_config, performance_tracker,
                                               mock_external_apis):
        """
        Test performance characteristics with APKs of various sizes.
        Helps identify performance bottlenecks and scaling issues.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for performance testing")
        
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        performance_results = []
        
        for apk_path in available_sample_apks:
            apk_size_mb = apk_path.stat().st_size / (1024 * 1024)
            
            # Skip very large APKs in automated testing
            if apk_size_mb > 100:  # 100MB limit
                continue
            
            try:
                performance_tracker.start()
                results = engine.analyze_apk(str(apk_path))
                performance_tracker.end()
                
                if results is not None:
                    duration = performance_tracker.duration()
                    
                    perf_result = {
                        'apk_name': apk_path.name,
                        'size_mb': apk_size_mb,
                        'duration_seconds': duration,
                        'mb_per_second': apk_size_mb / duration if duration > 0 else 0,
                        'analysis_success': True
                    }
                else:
                    perf_result = {
                        'apk_name': apk_path.name,
                        'size_mb': apk_size_mb,
                        'duration_seconds': 0,
                        'mb_per_second': 0,
                        'analysis_success': False
                    }
                
                performance_results.append(perf_result)
                
            except Exception as e:
                logging.warning(f"Performance test failed for {apk_path.name}: {e}")
        
        # Analyze performance characteristics
        if performance_results:
            successful_results = [r for r in performance_results if r['analysis_success']]
            
            if successful_results:
                avg_duration = sum(r['duration_seconds'] for r in successful_results) / len(successful_results)
                avg_throughput = sum(r['mb_per_second'] for r in successful_results) / len(successful_results)
                
                print(f"\nPerformance Analysis Results:")
                print(f"  Samples tested: {len(successful_results)}")
                print(f"  Average duration: {avg_duration:.2f}s")
                print(f"  Average throughput: {avg_throughput:.2f} MB/s")
                
                for result in successful_results:
                    print(f"  {result['apk_name']}: {result['size_mb']:.1f}MB in {result['duration_seconds']:.2f}s")
                
                # Performance assertions
                max_reasonable_duration = 300  # 5 minutes max
                slowest = max(successful_results, key=lambda x: x['duration_seconds'])
                assert slowest['duration_seconds'] < max_reasonable_duration, \
                    f"Slowest analysis ({slowest['apk_name']}) took {slowest['duration_seconds']:.2f}s, exceeds {max_reasonable_duration}s"
    
    def test_edge_case_handling(self, available_sample_apks, real_apk_test_config, mock_external_apis):
        """
        Test edge case handling with various APK characteristics.
        Validates robustness of the analysis pipeline.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for edge case testing")
        
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        edge_case_results = []
        
        for apk_path in available_sample_apks:
            try:
                results = engine.analyze_apk(str(apk_path))
                
                if results is not None:
                    results_dict = results.to_dict()
                    
                    # Analyze characteristics that might indicate edge cases
                    characteristics = {
                        'apk_name': apk_path.name,
                        'has_native_libs': bool(results_dict.get('apk_overview', {}).get('native_libraries')),
                        'large_string_count': len(results_dict.get('string_analysis', {}).get('all_strings', [])) > 10000,
                        'many_permissions': len(results_dict.get('permission_analysis', {}).get('all_permissions', [])) > 50,
                        'complex_manifest': len(str(results_dict.get('manifest_analysis', {}))) > 5000,
                        'analysis_errors': bool(results_dict.get('analysis_errors')),
                        'analysis_success': True
                    }
                else:
                    characteristics = {
                        'apk_name': apk_path.name,
                        'analysis_success': False,
                        'error': 'Analysis returned None'
                    }
                
                edge_case_results.append(characteristics)
                
            except Exception as e:
                edge_case_results.append({
                    'apk_name': apk_path.name,
                    'analysis_success': False,
                    'error': str(e),
                    'exception_type': type(e).__name__
                })
        
        # Analyze edge case handling
        successful_analyses = [r for r in edge_case_results if r['analysis_success']]
        failed_analyses = [r for r in edge_case_results if not r['analysis_success']]
        
        print(f"\nEdge Case Analysis:")
        print(f"  Total APKs: {len(edge_case_results)}")
        print(f"  Successful: {len(successful_analyses)}")
        print(f"  Failed: {len(failed_analyses)}")
        
        if successful_analyses:
            # Analyze characteristics
            with_native = [r for r in successful_analyses if r.get('has_native_libs')]
            large_strings = [r for r in successful_analyses if r.get('large_string_count')]
            many_perms = [r for r in successful_analyses if r.get('many_permissions')]
            
            print(f"  With native libraries: {len(with_native)}")
            print(f"  Large string count: {len(large_strings)}")
            print(f"  Many permissions: {len(many_perms)}")
        
        if failed_analyses:
            print("\nFailed analyses:")
            for failure in failed_analyses:
                print(f"  {failure['apk_name']}: {failure.get('error', 'Unknown error')}")
        
        # Assert reasonable success rate
        if edge_case_results:
            success_rate = len(successful_analyses) / len(edge_case_results)
            assert success_rate >= 0.5, f"Success rate too low: {success_rate:.2%}"
    
    def test_comprehensive_security_assessment(self, available_sample_apks,
                                             real_apk_test_config, mock_external_apis):
        """
        Test comprehensive security assessment across all available samples.
        Validates security analysis effectiveness and coverage.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for security testing")
        
        # Enable all security assessments
        security_config = real_apk_test_config.copy()
        security_config['security']['enable_owasp_assessment'] = True
        
        # Enable all OWASP assessments
        for assessment in security_config['security']['assessments']:
            security_config['security']['assessments'][assessment]['enabled'] = True
        
        config = Configuration(config_dict=security_config)
        engine = AnalysisEngine(config)
        
        security_summary = {
            'total_samples': 0,
            'samples_with_findings': 0,
            'total_findings': 0,
            'findings_by_category': {},
            'findings_by_severity': {},
            'average_risk_score': 0
        }
        
        risk_scores = []
        
        for apk_path in available_sample_apks:
            try:
                results = engine.analyze_apk(str(apk_path))
                
                if results is not None:
                    results_dict = results.to_dict()
                    security_assessment = results_dict.get('security_assessment', {})
                    
                    if security_assessment:
                        security_summary['total_samples'] += 1
                        
                        findings = security_assessment.get('findings', [])
                        risk_score = security_assessment.get('risk_score', 0)
                        
                        if findings:
                            security_summary['samples_with_findings'] += 1
                            security_summary['total_findings'] += len(findings)
                            
                            # Categorize findings
                            for finding in findings:
                                category = finding.get('category', 'Unknown')
                                severity = finding.get('severity', 'Unknown')
                                
                                security_summary['findings_by_category'][category] = \
                                    security_summary['findings_by_category'].get(category, 0) + 1
                                security_summary['findings_by_severity'][severity] = \
                                    security_summary['findings_by_severity'].get(severity, 0) + 1
                        
                        risk_scores.append(risk_score)
                
            except Exception as e:
                logging.warning(f"Security assessment failed for {apk_path.name}: {e}")
        
        # Calculate average risk score
        if risk_scores:
            security_summary['average_risk_score'] = sum(risk_scores) / len(risk_scores)
        
        # Print security assessment summary
        print(f"\nComprehensive Security Assessment Summary:")
        print(f"  Total samples analyzed: {security_summary['total_samples']}")
        print(f"  Samples with findings: {security_summary['samples_with_findings']}")
        print(f"  Total findings: {security_summary['total_findings']}")
        print(f"  Average risk score: {security_summary['average_risk_score']:.2f}")
        
        if security_summary['findings_by_category']:
            print(f"  Findings by category:")
            for category, count in security_summary['findings_by_category'].items():
                print(f"    {category}: {count}")
        
        if security_summary['findings_by_severity']:
            print(f"  Findings by severity:")
            for severity, count in security_summary['findings_by_severity'].items():
                print(f"    {severity}: {count}")
        
        # Validate security assessment is working appropriately for sample types
        if security_summary['total_samples'] > 0:
            # Expectations vary based on sample composition
            if security_summary['potentially_malicious_samples'] > 0:
                # If we have malicious samples, should detect some issues
                assert security_summary['total_findings'] > 0, \
                    "Security assessment should find findings in malicious samples"
                print(f"  ✓ Security assessment appropriately detected issues in malicious samples")
            elif security_summary['clean_samples'] > 0 and security_summary['potentially_malicious_samples'] == 0:
                # If we only have clean samples, minimal findings are expected
                print(f"  ✓ Security assessment completed on clean samples (minimal findings expected)")
                print(f"    Findings detected: {security_summary['total_findings']} (reasonable for clean samples)")
            else:
                # Mixed or unknown samples - should work without errors
                print(f"  ✓ Security assessment completed successfully on {security_summary['total_samples']} samples")

@pytest.mark.real_apk
@pytest.mark.local_dev
class TestAdvancedRealAPKScenarios:
    """Advanced scenarios for local development testing"""
    
    def test_large_apk_handling(self, available_sample_apks, real_apk_test_config, mock_external_apis):
        """Test handling of large APK files (>10MB)"""
        large_apks = [apk for apk in available_sample_apks 
                     if apk.stat().st_size > 10 * 1024 * 1024]
        
        if not large_apks:
            pytest.skip("No large APK samples available")
        
        config = Configuration(config_dict=real_apk_test_config)
        engine = AnalysisEngine(config)
        
        for apk_path in large_apks[:2]:  # Test max 2 large APKs to save time
            try:
                results = engine.analyze_apk(str(apk_path))
                assert results is not None, f"Large APK analysis should not fail: {apk_path.name}"
                
                # Validate key results are still generated
                results_dict = results.to_dict()
                assert 'apk_overview' in results_dict, "Large APK should have overview"
                
            except Exception as e:
                pytest.fail(f"Large APK analysis failed for {apk_path.name}: {e}")
    
    def test_timeout_handling(self, available_sample_apks, mock_external_apis):
        """Test timeout handling with real APKs"""
        if not available_sample_apks:
            pytest.skip("No APK samples available for timeout testing")
        
        # Use very short timeouts to test timeout handling
        timeout_config = {
            'modules': {
                'apk_overview': {'enabled': True, 'timeout': 1},  # Very short timeout
                'string_analysis': {'enabled': True, 'timeout': 1}
            }
        }
        
        config = Configuration(config_dict=timeout_config)
        engine = AnalysisEngine(config)
        
        # Test with first available APK
        apk_path = available_sample_apks[0]
        
        try:
            results = engine.analyze_apk(str(apk_path))
            # Should either succeed quickly or handle timeout gracefully
            if results is not None:
                results_dict = results.to_dict()
                # Should have some partial results even with timeouts
                assert isinstance(results_dict, dict), "Should return valid results structure"
        except Exception as e:
            # Timeout exceptions should be handled gracefully
            assert "timeout" in str(e).lower() or "time" in str(e).lower(), \
                f"Should be timeout-related error: {e}"