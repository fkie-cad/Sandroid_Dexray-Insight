#!/usr/bin/env python3
"""
CLI Integration Tests

Tests the complete CLI-to-output pipeline to catch configuration
and display bugs that unit tests might miss.
"""

import pytest
import subprocess
import tempfile
import os
from pathlib import Path


class TestCLIIntegration:
    """Test complete CLI workflows"""
    
    @pytest.fixture
    def sample_apk(self):
        """Create or use a sample APK for testing"""
        # In real implementation, use a minimal test APK
        # For now, return a placeholder
        return "test_sample.apk"
    
    def test_security_flag_enables_version_analysis(self, sample_apk):
        """Test that -s flag properly enables version analysis"""
        # Run with -s flag
        result = subprocess.run([
            "dexray-insight", "-s", sample_apk
        ], capture_output=True, text=True, timeout=300)
        
        # Check that version analysis ran
        assert "📚 LIBRARY VERSION ANALYSIS" in result.stdout
        assert "years behind" in result.stdout
        # Should appear in summary, not during analysis
        assert result.stdout.index("📚 LIBRARY VERSION ANALYSIS") > result.stdout.index("📱 DEXRAY INSIGHT ANALYSIS SUMMARY")
    
    def test_without_security_flag_skips_version_analysis(self, sample_apk):
        """Test that without -s flag, version analysis is skipped"""
        result = subprocess.run([
            "dexray-insight", sample_apk
        ], capture_output=True, text=True, timeout=300)
        
        # Should not have version analysis section
        assert "📚 LIBRARY VERSION ANALYSIS" not in result.stdout
        assert "VERSION ANALYSIS SKIPPED" in result.stdout or "version analysis only runs during security analysis" in result.stdout.lower()
    
    def test_config_file_override_behavior(self, sample_apk):
        """Test that CLI flags properly override config file settings"""
        # Create temp config with security disabled
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
security:
  enable_owasp_assessment: false
modules:
  library_detection:
    version_analysis:
      enabled: true
      security_analysis_only: true
""")
            config_path = f.name
        
        try:
            # Run with -s flag and custom config
            result = subprocess.run([
                "dexray-insight", "-c", config_path, "-s", sample_apk
            ], capture_output=True, text=True, timeout=300)
            
            # CLI flag should override config file
            assert "📚 LIBRARY VERSION ANALYSIS" in result.stdout
            assert result.returncode == 0
            
        finally:
            os.unlink(config_path)
    
    def test_version_analysis_display_location(self, sample_apk):
        """Test that version analysis appears in the correct location in output"""
        result = subprocess.run([
            "dexray-insight", "-s", sample_apk
        ], capture_output=True, text=True, timeout=300)
        
        output = result.stdout
        
        # Find positions of key sections
        summary_pos = output.find("📱 DEXRAY INSIGHT ANALYSIS SUMMARY")
        lib_detection_pos = output.find("📚 LIBRARY DETECTION")
        version_analysis_pos = output.find("📚 LIBRARY VERSION ANALYSIS")
        security_assessment_pos = output.find("🛡️  SECURITY ASSESSMENT")
        
        # Verify correct ordering
        assert summary_pos < lib_detection_pos, "Summary should come before library detection"
        assert lib_detection_pos < version_analysis_pos, "Version analysis should come after library detection"
        assert version_analysis_pos < security_assessment_pos, "Version analysis should come before security assessment"
    
    def test_version_analysis_content_format(self, sample_apk):
        """Test that version analysis output has correct format"""
        result = subprocess.run([
            "dexray-insight", "-s", sample_apk
        ], capture_output=True, text=True, timeout=300)
        
        output = result.stdout
        
        if "📚 LIBRARY VERSION ANALYSIS" in output:
            # Extract version analysis section
            start = output.find("📚 LIBRARY VERSION ANALYSIS")
            end = output.find("="*80, start + 1)  # Next section separator
            version_section = output[start:end] if end > start else output[start:]
            
            # Check format elements
            assert "Version analysis grouping:" in version_section
            assert "SUMMARY:" in version_section
            assert "Total libraries analyzed:" in version_section
            
            # Check for risk categories (if libraries are outdated)
            risk_indicators = ["CRITICAL RISK", "HIGH RISK", "MEDIUM RISK", "OUTDATED LIBRARIES", "CURRENT LIBRARIES"]
            has_risk_categories = any(indicator in version_section for indicator in risk_indicators)
            
            # If we have version analysis, we should have some categorization
            if "libraries analyzed" in version_section and "0 libraries analyzed" not in version_section:
                assert has_risk_categories, f"Version analysis section should have risk categories. Content: {version_section[:500]}"


class TestConfigurationIntegration:
    """Test configuration loading and precedence"""
    
    def test_default_config_loading(self):
        """Test that dexray.yaml is automatically loaded"""
        # Check if dexray.yaml exists and affects behavior
        config_path = Path.cwd() / "dexray.yaml"
        
        if config_path.exists():
            # Read current config
            with open(config_path) as f:
                content = f.read()
            
            # Should not have explicit enable_owasp_assessment: false
            # (it should be commented out after our fix)
            lines = content.split('\n')
            owasp_lines = [line for line in lines if 'enable_owasp_assessment' in line]
            
            for line in owasp_lines:
                if not line.strip().startswith('#'):
                    # If there's an uncommented line, it shouldn't be false
                    assert 'false' not in line.lower(), f"Found uncommented enable_owasp_assessment: false in dexray.yaml: {line}"
    
    def test_cli_args_parsing(self):
        """Test CLI argument parsing in isolation"""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
        
        from dexray_insight.asam import parse_arguments, create_configuration_from_args
        import argparse
        
        # Mock sys.argv
        original_argv = sys.argv
        try:
            sys.argv = ['dexray-insight', '-s', 'test.apk']
            
            args = parse_arguments()
            assert hasattr(args, 'sec')
            assert args.sec == True
            
            config = create_configuration_from_args(args)
            assert config.enable_security_assessment == True
            
            # Check dict representation
            config_dict = config.to_dict()
            assert config_dict['security']['enable_owasp_assessment'] == True
            
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    pytest.main([__file__, "-v"])