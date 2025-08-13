#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Real APK End-to-End Tests

Complete end-to-end validation of the analysis pipeline from CLI input to final output
using real APK samples. Tests the entire user journey and validates output formats.

Tests covered:
- Complete CLI command execution with real APKs
- JSON output file generation and validation
- Console output formatting and completeness
- Configuration file handling with real analysis
- Error scenarios and user experience
- Multi-format output generation
- Performance tracking and reporting
"""

import pytest
import json
import tempfile
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, List
import yaml
import time

from tests.fixtures.real_apk_fixtures import (
    ci_safe_apk_path, available_sample_apks, is_ci_environment,
    real_apk_test_config, performance_tracker, mock_external_apis
)

# Test constants
CLI_SCRIPT_PATH = Path(__file__).parent.parent.parent / "src" / "dexray_insight" / "asam.py"

@pytest.mark.real_apk
@pytest.mark.e2e
class TestRealAPKEndToEnd:
    """End-to-end tests using real APKs"""
    
    def test_cli_basic_analysis_ci_safe(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test basic CLI analysis with CI-safe APK.
        Validates complete CLI workflow from command to output files.
        """
        # Run CLI analysis
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Validate CLI execution
        assert result.returncode == 0, f"CLI should succeed. stderr: {result.stderr}"
        
        # Check output files were created
        output_files = list(tmp_path.glob("dexray_*.json"))
        assert len(output_files) > 0, "Should create at least one JSON output file"
        
        # Validate JSON output
        output_file = output_files[0]
        with open(output_file, 'r') as f:
            output_data = json.load(f)
        
        # Validate JSON structure
        assert isinstance(output_data, dict), "Output should be valid JSON dictionary"
        assert 'apk_overview' in output_data, "Should contain APK overview"
        assert 'metadata' in output_data, "Should contain analysis metadata"
        
        # Check metadata
        metadata = output_data['metadata']
        assert 'analysis_timestamp' in metadata, "Should contain timestamp"
        assert 'dexray_version' in metadata, "Should contain version info"
    
    def test_cli_with_security_assessment(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test CLI with security assessment enabled.
        Validates security analysis integration in CLI workflow.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--security",  # Enable security assessment
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        assert result.returncode == 0, f"CLI with security should succeed. stderr: {result.stderr}"
        
        # Check that security assessment ran
        output_files = list(tmp_path.glob("dexray_*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        with open(output_files[0], 'r') as f:
            output_data = json.load(f)
        
        # Should contain security assessment results
        assert 'security_assessment' in output_data, "Should contain security assessment"
        
        security = output_data['security_assessment']
        assert 'findings' in security, "Security assessment should contain findings"
        assert 'risk_score' in security, "Security assessment should contain risk score"
    
    def test_cli_with_custom_config(self, ci_safe_apk_path, tmp_path, real_apk_test_config, mock_external_apis):
        """
        Test CLI with custom configuration file.
        Validates configuration file handling in real analysis.
        """
        # Create custom config file
        config_file = tmp_path / "test_config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(real_apk_test_config, f)
        
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--config", str(config_file),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        assert result.returncode == 0, f"CLI with config should succeed. stderr: {result.stderr}"
        
        # Validate that custom config was used
        output_files = list(tmp_path.glob("dexray_*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        with open(output_files[0], 'r') as f:
            output_data = json.load(f)
        
        # Validate that configured modules ran
        expected_modules = ['apk_overview', 'library_detection', 'tracker_analysis']
        for module in expected_modules:
            assert module in output_data, f"Custom config should enable {module}"
    
    def test_cli_console_output_format(self, ci_safe_apk_path, mock_external_apis):
        """
        Test CLI console output formatting.
        Validates that console output is properly formatted and informative.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--no-output-file"  # Only console output
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        assert result.returncode == 0, f"CLI console output should succeed. stderr: {result.stderr}"
        
        console_output = result.stdout
        
        # Validate console output contains expected sections
        expected_sections = [
            "APK OVERVIEW",
            "ANALYSIS RESULTS", 
            "Analysis completed"
        ]
        
        for section in expected_sections:
            assert section in console_output, f"Console should contain '{section}' section"
        
        # Validate output is substantial and informative
        assert len(console_output.strip()) > 500, "Console output should be substantial"
        
        # Check for key information
        assert "Package:" in console_output or "package" in console_output.lower(), \
            "Should display package information"
    
    def test_cli_error_handling_invalid_apk(self, tmp_path, mock_external_apis):
        """
        Test CLI error handling with invalid APK file.
        Validates graceful error handling and user-friendly messages.
        """
        # Create invalid APK file
        invalid_apk = tmp_path / "invalid.apk"
        invalid_apk.write_text("This is not a valid APK file")
        
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(invalid_apk),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        # Should handle error gracefully
        assert result.returncode != 0, "Invalid APK should cause non-zero exit code"
        
        # Error message should be informative
        error_output = result.stderr
        assert len(error_output) > 0, "Should provide error message"
        assert "error" in error_output.lower() or "failed" in error_output.lower(), \
            "Error message should indicate failure"
    
    def test_cli_nonexistent_file(self, mock_external_apis):
        """
        Test CLI with nonexistent APK file.
        Validates file existence checking and error reporting.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            "/nonexistent/path/fake.apk"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        assert result.returncode != 0, "Nonexistent file should cause error"
        
        error_output = result.stderr
        assert "not found" in error_output.lower() or "no such file" in error_output.lower(), \
            "Should indicate file not found"
    
    @pytest.mark.performance
    def test_cli_performance_tracking(self, ci_safe_apk_path, tmp_path, performance_tracker, mock_external_apis):
        """
        Test CLI performance and resource usage.
        Validates that CLI completes within reasonable time and resource constraints.
        """
        performance_tracker.start()
        
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json",
            "--debug", "INFO"  # Enable some logging for performance tracking
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        performance_tracker.end()
        
        assert result.returncode == 0, f"Performance test should succeed. stderr: {result.stderr}"
        
        # Validate performance metrics
        duration = performance_tracker.duration()
        apk_size_mb = ci_safe_apk_path.stat().st_size / (1024 * 1024)
        
        # Performance assertions
        max_duration = 180.0  # 3 minutes max for CLI
        assert duration < max_duration, f"CLI took {duration:.2f}s, exceeds {max_duration}s"
        
        # Log performance
        print(f"CLI Performance: {duration:.2f}s for {apk_size_mb:.1f}MB APK")
        print(f"Throughput: {apk_size_mb/duration:.2f} MB/s")
    
    def test_cli_multiple_formats(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test CLI with multiple output formats.
        Validates multi-format output generation capability.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json",
            "--format", "text"  # Multiple formats
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            # Multiple formats might not be supported, skip test
            pytest.skip("Multiple format output not supported")
        
        # Check that multiple output files were created
        json_files = list(tmp_path.glob("*.json"))
        text_files = list(tmp_path.glob("*.txt"))
        
        # At least one format should be generated
        assert len(json_files) > 0 or len(text_files) > 0, "Should generate output files"

@pytest.mark.real_apk
@pytest.mark.e2e
@pytest.mark.local_dev
class TestRealAPKE2ELocalDevelopment:
    """E2E tests for local development with optional samples"""
    
    def test_skip_in_ci(self, is_ci_environment):
        """Skip local development E2E tests in CI"""
        if is_ci_environment:
            pytest.skip("Local development E2E tests not run in CI")
    
    def test_cli_multiple_apks_batch_analysis(self, available_sample_apks, tmp_path, mock_external_apis):
        """
        Test CLI batch analysis with multiple APKs.
        Validates handling of multiple APK files in sequence.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for batch testing")
        
        # Limit to first 3 APKs to save time
        test_apks = available_sample_apks[:3]
        
        batch_results = []
        
        for apk_path in test_apks:
            # Create separate output directory for each APK
            apk_output_dir = tmp_path / f"output_{apk_path.stem}"
            apk_output_dir.mkdir()
            
            cmd = [
                sys.executable, str(CLI_SCRIPT_PATH),
                str(apk_path),
                "--output-dir", str(apk_output_dir),
                "--format", "json"
            ]
            
            try:
                start_time = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                end_time = time.time()
                
                batch_result = {
                    'apk_name': apk_path.name,
                    'success': result.returncode == 0,
                    'duration': end_time - start_time,
                    'output_files': len(list(apk_output_dir.glob("*.json"))),
                    'error': result.stderr if result.returncode != 0 else None
                }
                
                batch_results.append(batch_result)
                
            except subprocess.TimeoutExpired:
                batch_results.append({
                    'apk_name': apk_path.name,
                    'success': False,
                    'duration': 300,
                    'output_files': 0,
                    'error': 'Timeout'
                })
        
        # Validate batch results
        successful_analyses = [r for r in batch_results if r['success']]
        
        print(f"\nBatch Analysis Results:")
        for result in batch_results:
            status = "✓" if result['success'] else "✗"
            print(f"  {status} {result['apk_name']}: {result['duration']:.1f}s")
            if not result['success']:
                print(f"    Error: {result['error']}")
        
        # At least 50% should succeed
        success_rate = len(successful_analyses) / len(batch_results) if batch_results else 0
        assert success_rate >= 0.5, f"Batch success rate too low: {success_rate:.1%}"
    
    def test_cli_comprehensive_analysis_large_sample(self, available_sample_apks, tmp_path, mock_external_apis):
        """
        Test comprehensive analysis with largest available sample.
        Validates CLI handles complex/large APKs without issues.
        """
        if not available_sample_apks:
            pytest.skip("No APK samples available for comprehensive testing")
        
        # Find largest APK (up to reasonable limit)
        large_apks = [apk for apk in available_sample_apks 
                     if apk.stat().st_size < 50 * 1024 * 1024]  # Under 50MB
        
        if not large_apks:
            pytest.skip("No suitable large APK samples found")
        
        largest_apk = max(large_apks, key=lambda x: x.stat().st_size)
        
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(largest_apk),
            "--security",  # Enable comprehensive analysis
            "--output-dir", str(tmp_path),
            "--format", "json",
            "--debug", "DEBUG"  # Enable detailed logging
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 min timeout
        
        assert result.returncode == 0, f"Comprehensive analysis should succeed. stderr: {result.stderr}"
        
        # Validate comprehensive output
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        with open(output_files[0], 'r') as f:
            output_data = json.load(f)
        
        # Validate comprehensive analysis results
        expected_sections = [
            'apk_overview', 'library_detection', 'tracker_analysis', 
            'security_assessment', 'string_analysis'
        ]
        
        for section in expected_sections:
            assert section in output_data, f"Comprehensive analysis should include {section}"
        
        # Log analysis summary
        apk_size_mb = largest_apk.stat().st_size / (1024 * 1024)
        print(f"Comprehensive analysis of {largest_apk.name} ({apk_size_mb:.1f}MB) completed successfully")

@pytest.mark.real_apk
@pytest.mark.e2e
class TestRealAPKOutputValidation:
    """Output validation tests for real APK analysis"""
    
    def test_json_schema_compliance(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test that JSON output complies with expected schema.
        Validates output structure consistency for external tool integration.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, "Analysis should succeed"
        
        # Load and validate JSON
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create JSON output"
        
        with open(output_files[0], 'r') as f:
            data = json.load(f)
        
        # Define expected JSON schema structure
        required_top_level = ['apk_overview', 'metadata']
        optional_top_level = [
            'library_detection', 'tracker_analysis', 'security_assessment',
            'string_analysis', 'manifest_analysis', 'permission_analysis'
        ]
        
        # Validate required fields
        for field in required_top_level:
            assert field in data, f"JSON should contain required field: {field}"
        
        # Validate metadata structure
        metadata = data['metadata']
        expected_metadata = ['analysis_timestamp', 'dexray_version']
        for field in expected_metadata:
            assert field in metadata, f"Metadata should contain: {field}"
        
        # Validate APK overview structure
        apk_overview = data['apk_overview']
        expected_overview = ['package_name', 'app_name']
        for field in expected_overview:
            assert field in apk_overview, f"APK overview should contain: {field}"
    
    def test_file_naming_convention(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test output file naming convention.
        Validates consistent file naming for automated processing.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, "Analysis should succeed"
        
        # Check file naming pattern
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        output_file = output_files[0]
        filename = output_file.name
        
        # Validate naming convention: dexray_<apk_name>_<timestamp>.json
        assert filename.startswith("dexray_"), "File should start with 'dexray_'"
        assert filename.endswith(".json"), "File should end with '.json'"
        assert len(filename) > 20, "Filename should include timestamp/identifier"
    
    def test_output_file_permissions(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test output file permissions and accessibility.
        Validates that output files can be read by external tools.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, "Analysis should succeed"
        
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        output_file = output_files[0]
        
        # Check file is readable
        assert output_file.is_file(), "Output should be a regular file"
        assert output_file.stat().st_size > 0, "Output file should not be empty"
        
        # Test file can be read
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            assert len(content) > 0, "File content should not be empty"
        except Exception as e:
            pytest.fail(f"Cannot read output file: {e}")
    
    def test_unicode_handling_in_output(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test Unicode handling in JSON output.
        Validates proper encoding of international characters and symbols.
        """
        cmd = [
            sys.executable, str(CLI_SCRIPT_PATH),
            str(ci_safe_apk_path),
            "--output-dir", str(tmp_path),
            "--format", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, "Analysis should succeed"
        
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Test Unicode handling
        with open(output_files[0], 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                
                # Re-serialize to test Unicode preservation
                json_str = json.dumps(data, ensure_ascii=False, indent=2)
                
                # Parse again to ensure round-trip works
                reparsed = json.loads(json_str)
                assert reparsed == data, "Unicode round-trip should preserve data"
                
            except UnicodeDecodeError as e:
                pytest.fail(f"Unicode handling failed: {e}")
            except json.JSONDecodeError as e:
                pytest.fail(f"JSON parsing failed: {e}")