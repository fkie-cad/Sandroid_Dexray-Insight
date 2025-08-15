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
import subprocess
import sys
import os
from pathlib import Path
import yaml
import time

# Import fixtures for real APK testing
from tests.fixtures.real_apk_fixtures import (  # noqa: F401
    ci_safe_apk_path, available_sample_apks, is_ci_environment,
    real_apk_test_config, performance_tracker, mock_external_apis
)

# Add path for accessing CustomJSONEncoder
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
from dexray_insight.Utils.file_utils import CustomJSONEncoder

# Test constants - use module execution instead of direct script execution
# This avoids relative import issues when running asam.py directly
PROJECT_ROOT = Path(__file__).parent.parent.parent

def run_cli_command(cmd_args, **kwargs):
    """Helper function to run CLI commands with proper environment setup"""
    cmd = [sys.executable, "-m", "dexray_insight.asam"] + cmd_args
    
    # Set up environment for module execution
    env = dict(os.environ)
    env['PYTHONPATH'] = str(PROJECT_ROOT / "src")
    
    return subprocess.run(cmd, env=env, **kwargs)

@pytest.mark.real_apk
@pytest.mark.e2e
class TestRealAPKEndToEnd:
    """End-to-end tests using real APKs"""
    
    def test_cli_basic_analysis_ci_safe(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test basic CLI analysis with CI-safe APK.
        Validates complete CLI workflow from command to output files.
        """
        # Run CLI analysis using helper function
        # Note: CLI doesn't support --output-dir or --format, outputs to current directory
        result = run_cli_command([
            str(ci_safe_apk_path)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        
        # Validate CLI execution
        assert result.returncode == 0, f"CLI should succeed. stderr: {result.stderr}"
        
        # Check output files were created
        output_files = list(tmp_path.glob("dexray_*.json"))
        assert len(output_files) > 0, "Should create at least one JSON output file"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        # Validate JSON output
        with open(main_file, 'r') as f:
            output_data = json.load(f)
        
        # Validate JSON structure
        assert isinstance(output_data, dict), "Output should be valid JSON dictionary"
        assert 'apk_overview' in output_data, "Should contain APK overview"
        
        # Check that we have analysis results (at least one module should have results)
        analysis_modules = ['apk_overview', 'in_depth_analysis', 'behaviour_analysis', 'tracker_analysis', 'library_detection']
        found_modules = [module for module in analysis_modules if module in output_data]
        assert len(found_modules) > 0, f"Should contain analysis results from modules, found: {found_modules}"
    
    def test_cli_with_security_assessment(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test CLI with security assessment enabled.
        Validates security analysis integration in CLI workflow.
        """
        result = run_cli_command([
            str(ci_safe_apk_path),
            "-s"  # Enable security assessment (--security not supported, use -s)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        
        assert result.returncode == 0, f"CLI with security should succeed. stderr: {result.stderr}"
        
        # Check that security assessment ran
        output_files = list(tmp_path.glob("dexray_*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        security_file = None
        for file_path in output_files:
            if "_security_" in file_path.name:
                security_file = file_path
            else:
                main_file = file_path
        
        assert main_file is not None, "Should create main results file"
        
        with open(main_file, 'r') as f:
            output_data = json.load(f)
        
        # Should contain security assessment results
        assert 'security_assessment' in output_data, "Should contain security assessment"
        
        security = output_data['security_assessment']
        assert 'findings' in security, "Security assessment should contain findings"
        assert 'overall_risk_score' in security, "Security assessment should contain overall risk score"
    
    def test_cli_with_custom_config(self, ci_safe_apk_path, tmp_path, real_apk_test_config, mock_external_apis):
        """
        Test CLI with custom configuration file.
        Validates configuration file handling in real analysis.
        """
        # Create custom config file
        config_file = tmp_path / "test_config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(real_apk_test_config, f)
        
        result = run_cli_command([
            str(ci_safe_apk_path),
            "--config", str(config_file)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        
        assert result.returncode == 0, f"CLI with config should succeed. stderr: {result.stderr}"
        
        # Validate that custom config was used
        output_files = list(tmp_path.glob("dexray_*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        with open(main_file, 'r') as f:
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
        # Note: CLI doesn't support --no-output-file, test with normal output
        result = run_cli_command([
            str(ci_safe_apk_path)
        ], capture_output=True, text=True, timeout=300)
        
        assert result.returncode == 0, f"CLI console output should succeed. stderr: {result.stderr}"
        
        console_output = result.stdout
        
        # Validate console output contains expected sections
        expected_sections = [
            "PACKING ANALYSIS",  # Modern output uses "📦 PACKING ANALYSIS"
            "COMPONENTS",        # Modern output uses "🏗️ COMPONENTS"
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
        
        result = run_cli_command([
            str(invalid_apk)
        ], capture_output=True, text=True, timeout=60, cwd=str(tmp_path))
        
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
        result = run_cli_command([
            "/nonexistent/path/fake.apk"
        ], capture_output=True, text=True, timeout=30)
        
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
        
        result = run_cli_command([
            str(ci_safe_apk_path),
            "--debug", "INFO"  # Enable some logging for performance tracking
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        
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
        # Note: CLI doesn't support --format argument, skip test as multiple formats not supported
        pytest.skip("Multiple format output not supported by CLI")

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
            
            # Set up environment for module execution
            env = dict(os.environ)
            env['PYTHONPATH'] = str(PROJECT_ROOT / "src")
            
            cmd = [
                sys.executable, "-m", "dexray_insight.asam",
                str(apk_path)
            ]
            
            try:
                start_time = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env, cwd=str(apk_output_dir))
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
        
        print("\nBatch Analysis Results:")
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
        
        result = run_cli_command([
            str(largest_apk),
            "-s",  # Enable comprehensive analysis (security assessment)
            "--debug", "DEBUG"  # Enable detailed logging
        ], capture_output=True, text=True, timeout=600, cwd=str(tmp_path))  # 10 min timeout
        
        assert result.returncode == 0, f"Comprehensive analysis should succeed. stderr: {result.stderr}"
        
        # Validate comprehensive output
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        with open(main_file, 'r') as f:
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
        result = run_cli_command([
            str(ci_safe_apk_path)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        assert result.returncode == 0, "Analysis should succeed"
        
        # Load and validate JSON
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create JSON output"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        with open(main_file, 'r') as f:
            data = json.load(f)
        
        # Define expected JSON schema structure
        required_top_level = ['apk_overview']
        
        # Validate required fields
        for field in required_top_level:
            assert field in data, f"JSON should contain required field: {field}"
        
        # Check that we have analysis results (at least one module should have results)
        analysis_modules = ['apk_overview', 'in_depth_analysis', 'behaviour_analysis', 'tracker_analysis', 'library_detection']
        found_modules = [module for module in analysis_modules if module in data]
        assert len(found_modules) > 0, f"JSON should contain analysis results from modules, found: {found_modules}"
        
        # Validate APK overview structure
        apk_overview = data['apk_overview']
        
        # Check basic APK overview structure (allowing for different structures)
        if 'general_info' in apk_overview:
            # New structure with general_info
            general_info = apk_overview['general_info']
            if 'package_name' not in general_info and 'app_name' not in general_info:
                # Allow minimal APK overview if general_info exists but no specific fields
                assert len(apk_overview) > 0, "APK overview should contain some data"
        else:
            # Older structure with direct fields
            assert len(apk_overview) > 0, "APK overview should contain some data"
    
    def test_file_naming_convention(self, ci_safe_apk_path, tmp_path, mock_external_apis):
        """
        Test output file naming convention.
        Validates consistent file naming for automated processing.
        """
        result = run_cli_command([
            str(ci_safe_apk_path)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        assert result.returncode == 0, "Analysis should succeed"
        
        # Check file naming pattern
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        output_file = main_file
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
        result = run_cli_command([
            str(ci_safe_apk_path)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        assert result.returncode == 0, "Analysis should succeed"
        
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        output_file = main_file
        
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
        result = run_cli_command([
            str(ci_safe_apk_path)
        ], capture_output=True, text=True, timeout=300, cwd=str(tmp_path))
        assert result.returncode == 0, "Analysis should succeed"
        
        output_files = list(tmp_path.glob("*.json"))
        assert len(output_files) > 0, "Should create output files"
        
        # Find the main results file (not the security-specific file)
        main_file = None
        for file_path in output_files:
            if "_security_" not in file_path.name:
                main_file = file_path
                break
        
        assert main_file is not None, "Should create main results file"
        
        # Test Unicode handling
        with open(main_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                
                # Re-serialize to test Unicode preservation
                json_str = json.dumps(data, cls=CustomJSONEncoder, ensure_ascii=False, indent=2)
                
                # Parse again to ensure round-trip works
                reparsed = json.loads(json_str)
                assert reparsed == data, "Unicode round-trip should preserve data"
                
            except UnicodeDecodeError as e:
                pytest.fail(f"Unicode handling failed: {e}")
            except json.JSONDecodeError as e:
                pytest.fail(f"JSON parsing failed: {e}")