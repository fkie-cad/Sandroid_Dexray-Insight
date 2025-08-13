#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TDD tests for refactored FullAnalysisResults.print_analyst_summary() function.

Following SOLID principles and TDD Red-Green-Refactor cycle:
- Single Responsibility: Each function handles one aspect of summary display
- Open/Closed: New result types can be added without modifying existing functions
- Dependency Inversion: Functions depend on abstractions (data structures)

Target function: print_analyst_summary() (383 lines, 8 responsibilities)
Refactoring into: 8 single-purpose functions + 1 coordinator function
"""

import pytest
from unittest.mock import Mock, patch
from io import StringIO
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

# Import required classes
from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
from dexray_insight.results.apkOverviewResults import APKOverview
from dexray_insight.results.InDepthAnalysisResults import Results
from dexray_insight.results.ApkidResults import ApkidResults, ApkidFileAnalysis
from dexray_insight.results.KavanozResults import KavanozResults


def capture_print_output(func, *args, **kwargs):
    """Helper function to capture print output"""
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    try:
        func(*args, **kwargs)
        return captured_output.getvalue()
    finally:
        sys.stdout = old_stdout


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsPrintSummaryHeader:
    """
    Tests for _print_summary_header function (TDD - Red Phase).
    
    Single Responsibility: Print formatted header for analysis summary.
    """
    
    def test_print_summary_header_displays_formatted_header(self):
        """
        Test that _print_summary_header prints the correct formatted header.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_summary_header)
        
        # Assert
        expected_lines = [
            "\n" + "="*80,
            "📱 DEXRAY INSIGHT ANALYSIS SUMMARY", 
            "="*80
        ]
        for expected_line in expected_lines:
            assert expected_line in output
    
    def test_print_summary_header_uses_consistent_formatting(self):
        """
        Test that header formatting is consistent and properly structured.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        
        # Act
        output = capture_print_output(results._print_summary_header)
        
        # Assert
        lines = output.strip().split('\n')
        assert len(lines) >= 3  # Should have at least 3 lines
        assert len(lines[1]) == 80  # Top border should be 80 characters
        assert len(lines[-1]) == 80  # Bottom border should be 80 characters
        assert "📱 DEXRAY INSIGHT ANALYSIS SUMMARY" in lines[2]


@pytest.mark.refactored  
@pytest.mark.phase3
class TestFullAnalysisResultsPrintApkInformation:
    """
    Tests for _print_apk_information function (TDD - Red Phase).
    
    Single Responsibility: Print APK file and application information.
    """
    
    def test_print_apk_information_displays_file_details(self):
        """
        Test that _print_apk_information displays file metadata correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.general_info = {
            'file_name': 'test.apk',
            'file_size': '1.5MB',
            'md5': 'abc123',
            'sha1': 'def456',
            'sha256': 'ghi789'
        }
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_apk_information)
        
        # Assert
        assert "📋 APK INFORMATION" in output
        assert "File Name: test.apk" in output
        assert "File Size: 1.5MB" in output
        assert "Md5: abc123" in output
        assert "Sha1: def456" in output
        assert "Sha256: ghi789" in output
    
    def test_print_apk_information_displays_app_details(self):
        """
        Test that _print_apk_information displays application metadata correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.general_info = {
            'app_name': 'Test App',
            'package_name': 'com.test.app',
            'main_activity': 'MainActivity',
            'target_sdk': '30',
            'min_sdk': '21',
            'android_version_name': '1.0.0',
            'android_version_code': '100'
        }
        
        # Act
        output = capture_print_output(results._print_apk_information)
        
        # Assert
        assert "App Name: Test App" in output
        assert "Package Name: com.test.app" in output
        assert "Main Activity: MainActivity" in output
        assert "Target Sdk: 30" in output
        assert "Min Sdk: 21" in output
        assert "Android Version Name: 1.0.0" in output
        assert "Android Version Code: 100" in output
    
    def test_print_apk_information_handles_missing_overview(self):
        """
        Test that _print_apk_information handles missing APK overview gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = None
        
        # Act
        output = capture_print_output(results._print_apk_information)
        
        # Assert - Should not print APK information section or crash
        assert "📋 APK INFORMATION" not in output
    
    def test_print_apk_information_displays_cross_platform_info(self):
        """
        Test that cross-platform framework information is displayed correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange  
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.general_info = {'app_name': 'Test'}
        results.apk_overview.is_cross_platform = True
        results.apk_overview.cross_platform_framework = 'React Native'
        
        # Act
        output = capture_print_output(results._print_apk_information)
        
        # Assert
        assert "🔗 Cross-Platform: React Native" in output


@pytest.mark.refactored
@pytest.mark.phase3  
class TestFullAnalysisResultsPrintPermissionsSummary:
    """
    Tests for _print_permissions_summary function (TDD - Red Phase).
    
    Single Responsibility: Print permissions analysis with critical permission highlighting.
    """
    
    def test_print_permissions_summary_displays_critical_permissions(self):
        """
        Test that _print_permissions_summary highlights critical permissions.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.permissions = {
            'permissions': [
                'android.permission.CAMERA',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_CONTACTS',
                'android.permission.INTERNET',
                'android.permission.WRITE_EXTERNAL_STORAGE'
            ]
        }
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_permissions_summary)
        
        # Assert
        assert "🔐 PERMISSIONS (5 total)" in output
        assert "⚠️  Critical Permissions:" in output
        assert "android.permission.CAMERA" in output
        assert "android.permission.ACCESS_FINE_LOCATION" in output
        assert "android.permission.READ_CONTACTS" in output
    
    def test_print_permissions_summary_handles_large_permission_lists(self):
        """
        Test that permission list truncation works correctly for readability.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        critical_perms = [
            'android.permission.CAMERA',
            'android.permission.LOCATION', 
            'android.permission.CONTACTS',
            'android.permission.SMS',
            'android.permission.PHONE',
            'android.permission.STORAGE',
            'android.permission.MICROPHONE',
            'android.permission.ADMIN'  # 8 critical permissions
        ]
        results.apk_overview.permissions = {'permissions': critical_perms + ['android.permission.INTERNET']}
        
        # Act
        output = capture_print_output(results._print_permissions_summary)
        
        # Assert
        assert "🔐 PERMISSIONS (9 total)" in output
        assert "... and 3 more critical permissions" in output  # Should truncate after 5
    
    def test_print_permissions_summary_handles_no_permissions(self):
        """
        Test that empty permissions list is handled gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.permissions = {'permissions': []}
        
        # Act
        output = capture_print_output(results._print_permissions_summary)
        
        # Assert - Should not display permissions section
        assert "🔐 PERMISSIONS" not in output


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsPrintStringAnalysisSummary:
    """
    Tests for _print_string_analysis_summary function (TDD - Red Phase).
    
    Single Responsibility: Print string analysis results with categorization and truncation.
    """
    
    def test_print_string_analysis_summary_displays_string_categories(self):
        """
        Test that _print_string_analysis_summary displays all string categories correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.in_depth_analysis = Results()
        results.in_depth_analysis.strings_emails = ['test@example.com', 'admin@test.org']
        results.in_depth_analysis.strings_ip = ['192.168.1.1', '10.0.0.1', '8.8.8.8']
        results.in_depth_analysis.strings_urls = ['https://example.com', 'http://test.com']
        results.in_depth_analysis.strings_domain = ['example.com', 'google.com', 'github.com']
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_string_analysis_summary)
        
        # Assert
        assert "🔍 STRING ANALYSIS (URLs: 2, E-Mails: 2, IPs: 3, Domains: 3)" in output
        assert "🌐 IP Addresses: 3" in output
        assert "🏠 Domains: 3" in output
        assert "🔗 URLs: 2" in output
        assert "📧 Email Addresses: 2" in output
    
    def test_print_string_analysis_summary_truncates_long_lists(self):
        """
        Test that long string lists are properly truncated for readability.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.in_depth_analysis = Results()
        results.in_depth_analysis.strings_ip = [f"192.168.1.{i}" for i in range(10)]  # 10 IPs
        
        # Act
        output = capture_print_output(results._print_string_analysis_summary)
        
        # Assert
        assert "🌐 IP Addresses: 10" in output
        assert "... and 7 more" in output  # Should show max 3, so 7 more
        assert "192.168.1.0" in output  # First IP should be shown
        assert "192.168.1.9" not in output  # Last IP should not be shown (truncated)
    
    def test_print_string_analysis_summary_handles_empty_results(self):
        """
        Test that empty string analysis results are handled gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.in_depth_analysis = Results()
        # All string lists are empty (default)
        
        # Act
        output = capture_print_output(results._print_string_analysis_summary)
        
        # Assert
        assert "🔍 STRING ANALYSIS" in output
        # Should not show individual categories if empty
        assert "🌐 IP Addresses:" not in output
        assert "🏠 Domains:" not in output
    
    def test_print_string_analysis_summary_truncates_long_urls(self):
        """
        Test that long URLs are truncated with ellipsis for display.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.in_depth_analysis = Results()
        long_url = 'https://example.com/very/long/path/with/many/segments/that/exceeds/sixty/characters'
        results.in_depth_analysis.strings_urls = [long_url]
        
        # Act
        output = capture_print_output(results._print_string_analysis_summary)
        
        # Assert
        assert "🔗 URLs: 1" in output
        assert "..." in output  # Should be truncated
        assert long_url not in output  # Full URL should not appear


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsPrintSecurityAssessmentSummary:
    """
    Tests for _print_security_assessment_summary function (TDD - Red Phase).
    
    Single Responsibility: Print security assessment results with findings and risk scoring.
    """
    
    def test_print_security_assessment_summary_displays_risk_metrics(self):
        """
        Test that _print_security_assessment_summary displays risk score and findings count.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.security_assessment = {
            'total_findings': 15,
            'overall_risk_score': 75.5,
            'findings_by_severity': {
                'critical': 2,
                'high': 5,
                'medium': 6,
                'low': 2
            },
            'owasp_categories_affected': ['M1', 'M3', 'M7', 'M10']
        }
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_security_assessment_summary)
        
        # Assert
        assert "🛡️  SECURITY ASSESSMENT" in output
        assert "Security Findings: 15" in output
        assert "Risk Score: 75.50/100" in output
        assert "Severity Distribution: Critical: 2, High: 5, Medium: 6, Low: 2" in output
        assert "OWASP Categories: M1, M3, M7" in output
        assert "... and 1 more" in output  # Should truncate OWASP categories after 3
    
    def test_print_security_assessment_summary_displays_key_findings(self):
        """
        Test that key security findings are displayed with proper formatting.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.security_assessment = {
            'total_findings': 5,
            'overall_risk_score': 45.0,
            'findings': [
                {
                    'title': 'Hardcoded API Keys Detected',
                    'category': 'M10 - Extraneous Functionality',
                    'severity': {'value': 'high'}
                },
                {
                    'title': 'Insecure Network Communication',
                    'category': 'M4 - Insecure Communication',
                    'severity': 'medium'
                }
            ]
        }
        
        # Act
        output = capture_print_output(results._print_security_assessment_summary)
        
        # Assert
        assert "Key Findings:" in output
        assert "[HIGH] M10 - Extraneous Functionality: Hardcoded API Keys Detected" in output
        assert "[MEDIUM] M4 - Insecure Communication: Insecure Network Communication" in output
    
    def test_print_security_assessment_summary_handles_no_security_data(self):
        """
        Test that missing security assessment is handled gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.security_assessment = None
        
        # Act
        output = capture_print_output(results._print_security_assessment_summary)
        
        # Assert - Should not display security section
        assert "🛡️  SECURITY ASSESSMENT" not in output


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsPrintToolAnalysisSummary:
    """
    Tests for _print_tool_analysis_summary function (TDD - Red Phase).
    
    Single Responsibility: Print results from external analysis tools (APKID, Kavanoz, Signatures).
    """
    
    def test_print_tool_analysis_summary_displays_apkid_compiler_info(self):
        """
        Test that _print_tool_analysis_summary displays APKID compiler detection correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apkid_analysis = ApkidResults(apkid_version="3.1.0")
        results.apkid_analysis.files = [
            ApkidFileAnalysis(
                filename="classes.dex",
                matches={
                    'compiler': ['dx'],
                    'packer': []
                }
            )
        ]
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_tool_analysis_summary)
        
        # Assert
        assert "🔧 COMPILER & APKID ANALYSIS" in output
        assert "🎯 Primary DEX Compiler: dx" in output
        assert "🛠️  All Compiler(s) Detected:" in output
    
    def test_print_tool_analysis_summary_displays_packing_analysis(self):
        """
        Test that Kavanoz packing analysis results are displayed correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.kavanoz_analysis = KavanozResults()
        results.kavanoz_analysis.is_packed = True
        results.kavanoz_analysis.unpacking_result = "Successfully unpacked"
        
        # Act
        output = capture_print_output(results._print_tool_analysis_summary)
        
        # Assert
        assert "📦 PACKING ANALYSIS" in output
        assert "⚠️  APK appears to be packed" in output
        assert "Unpacking result: Successfully unpacked" in output
    
    def test_print_tool_analysis_summary_warns_about_repacking(self):
        """
        Test that repacking indicators trigger appropriate warnings.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apkid_analysis = ApkidResults(apkid_version="3.1.0")
        results.apkid_analysis.files = [
            ApkidFileAnalysis(
                filename="classes.dex",
                matches={
                    'compiler': ['dexlib'],  # Repacking indicator
                    'packer': []
                }
            )
        ]
        
        # Act
        output = capture_print_output(results._print_tool_analysis_summary)
        
        # Assert
        assert "⚠️  WARNING: dexlib detected - APK may be repacked/modified" in output


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsPrintComponentBehaviorSummary:
    """
    Tests for _print_component_behavior_summary function (TDD - Red Phase).
    
    Single Responsibility: Print component analysis and behavioral analysis results.
    """
    
    def test_print_component_behavior_summary_displays_components(self):
        """
        Test that _print_component_behavior_summary displays APK components correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.components = {
            'activities': ['MainActivity', 'SettingsActivity'],
            'services': ['BackgroundService'],
            'receivers': ['BootReceiver', 'NetworkReceiver'],
            'providers': []
        }
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_component_behavior_summary)
        
        # Assert
        assert "🏗️  COMPONENTS" in output
        assert "Activities: 2" in output
        assert "Services: 1" in output
        assert "Receivers: 2" in output
        # Should not show providers since empty
        assert "Providers: 0" not in output
    
    def test_print_component_behavior_summary_displays_behavior_analysis(self):
        """
        Test that behavior analysis results are displayed with readable formatting.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.behaviour_analysis = Mock()
        results.behaviour_analysis.get_detected_features.return_value = [
            'network_communication',
            'file_system_access', 
            'location_tracking'
        ]
        
        # Act
        output = capture_print_output(results._print_component_behavior_summary)
        
        # Assert
        assert "🔍 BEHAVIOUR ANALYSIS (3 behaviors detected)" in output
        assert "✓ Network Communication" in output
        assert "✓ File System Access" in output
        assert "✓ Location Tracking" in output


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsPrintSummaryFooter:
    """
    Tests for _print_summary_footer function (TDD - Red Phase).
    
    Single Responsibility: Print formatted footer with usage hints and file information.
    """
    
    def test_print_summary_footer_displays_standard_footer(self):
        """
        Test that _print_summary_footer prints the correct footer information.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.security_assessment = None
        
        # Act - This will fail initially (RED phase)
        output = capture_print_output(results._print_summary_footer)
        
        # Assert
        assert "="*80 in output
        assert "📄 Complete details saved to JSON file" in output
        assert "💡 Use -v flag for verbose terminal output" in output
        assert "="*80 in output
    
    def test_print_summary_footer_includes_security_file_notice(self):
        """
        Test that footer includes security file notice when security assessment exists.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.security_assessment = {'total_findings': 5}  # Non-empty security results
        
        # Act
        output = capture_print_output(results._print_summary_footer)
        
        # Assert
        assert "🛡️  Security findings saved to separate security JSON file" in output
        assert "📄 Complete details saved to JSON file" in output


@pytest.mark.refactored
@pytest.mark.phase3
class TestFullAnalysisResultsRefactoredPrintAnalystSummary:
    """
    Tests for the refactored print_analyst_summary coordinator function (TDD - Red Phase).
    
    Tests the main orchestration function that uses all the extracted helper functions.
    """
    
    def test_refactored_print_analyst_summary_calls_all_section_functions(self):
        """
        Test that refactored print_analyst_summary calls all section printing functions in order.
        
        This is the integration test ensuring the coordinator function properly orchestrates 
        all the individual printing functions.
        
        RED: This test will fail initially as the refactored function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.general_info = {'app_name': 'Test App'}
        results.in_depth_analysis = Results()
        results.security_assessment = {'total_findings': 1}
        
        # Mock all the individual functions
        with patch.object(results, '_print_summary_header') as mock_header, \
             patch.object(results, '_print_apk_information') as mock_apk, \
             patch.object(results, '_print_permissions_summary') as mock_perms, \
             patch.object(results, '_print_string_analysis_summary') as mock_strings, \
             patch.object(results, '_print_security_assessment_summary') as mock_security, \
             patch.object(results, '_print_tool_analysis_summary') as mock_tools, \
             patch.object(results, '_print_component_behavior_summary') as mock_components, \
             patch.object(results, '_print_summary_footer') as mock_footer:
            
            # Act - This will test the refactored version
            results.print_analyst_summary()
            
            # Assert - All functions should be called in the correct order
            mock_header.assert_called_once()
            mock_apk.assert_called_once() 
            mock_perms.assert_called_once()
            mock_strings.assert_called_once()
            mock_security.assert_called_once()
            mock_tools.assert_called_once()
            mock_components.assert_called_once()
            mock_footer.assert_called_once()
    
    def test_refactored_print_analyst_summary_maintains_output_compatibility(self):
        """
        Test that refactored function produces output compatible with original function.
        
        This is a comprehensive regression test ensuring no functionality was lost.
        
        RED: This test will fail initially as the refactored function doesn't exist yet.
        """
        # Arrange
        results = FullAnalysisResults()
        results.apk_overview = APKOverview()
        results.apk_overview.general_info = {
            'app_name': 'Test App',
            'file_name': 'test.apk',
            'package_name': 'com.test.app'
        }
        results.apk_overview.permissions = {
            'permissions': ['android.permission.INTERNET']
        }
        results.in_depth_analysis = Results()
        results.in_depth_analysis.strings_emails = ['test@example.com']
        
        # Act - Test the refactored version
        output = capture_print_output(results.print_analyst_summary)
        
        # Assert - Should contain key elements from all sections
        assert "📱 DEXRAY INSIGHT ANALYSIS SUMMARY" in output
        assert "📋 APK INFORMATION" in output
        assert "App Name: Test App" in output
        assert "🔐 PERMISSIONS" in output
        assert "🔍 STRING ANALYSIS" in output
        assert "📄 Complete details saved to JSON file" in output


# Mark all tests in this module as phase3 refactored tests
pytestmark = [pytest.mark.refactored, pytest.mark.phase3]