#!/usr/bin/env python3
"""
Output Formatting Tests

Tests that ensure output appears in the correct format and location.
Prevents bugs where functionality works but appears in wrong place.
"""

import pytest
import sys
from pathlib import Path
from io import StringIO
from unittest.mock import patch, MagicMock

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
from dexray_insight.results.LibraryDetectionResults import DetectedLibrary, LibraryDetectionMethod, LibraryCategory, LibrarySource


class TestVersionAnalysisDisplayLocation:
    """Test version analysis appears in correct location"""
    
    @pytest.fixture
    def mock_libraries_with_versions(self):
        """Create mock libraries with version analysis data"""
        library1 = DetectedLibrary(
            name="Firebase Cloud Messaging",
            package_name="firebase-messaging",
            version="19.0.0",
            detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
            category=LibraryCategory.NETWORKING,
            confidence=0.95,
            evidence=["Test"],
            source=LibrarySource.PROPERTIES_FILES,
            smali_path="unknown/firebase-messaging.properties"
        )
        # Add version analysis results
        library1.years_behind = 6.0
        library1.security_risk = "CRITICAL"
        library1.version_recommendation = "Extremely outdated (6.0 years behind). Update immediately for security."
        
        library2 = DetectedLibrary(
            name="Google Play Services Base",
            package_name="play-services-base", 
            version="18.5.0",
            detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
            category=LibraryCategory.UTILITY,
            confidence=0.95,
            evidence=["Test"],
            source=LibrarySource.PROPERTIES_FILES,
            smali_path="unknown/play-services-base.properties"
        )
        # Add version analysis results
        library2.years_behind = 0.5
        library2.security_risk = "LOW"
        library2.version_recommendation = "Slightly outdated (0.5 years behind). Consider updating."
        
        return [library1, library2]
    
    @pytest.fixture
    def mock_library_detection_result(self, mock_libraries_with_versions):
        """Create mock library detection result"""
        result = MagicMock()
        result.detected_libraries = mock_libraries_with_versions
        return result
    
    @pytest.fixture
    def mock_security_assessment(self):
        """Create mock security assessment (indicates security analysis was run)"""
        return {
            'total_findings': 5,
            'overall_risk_score': 8.5,
            'findings_by_severity': {
                'high': 2,
                'medium': 2,
                'low': 1
            }
        }
    
    def test_version_analysis_appears_in_summary(self, mock_library_detection_result, mock_security_assessment):
        """Test that version analysis appears in the analyst summary"""
        # Create FullAnalysisResults with library detection and security assessment
        results = FullAnalysisResults()
        results.library_detection = mock_library_detection_result
        results.security_assessment = mock_security_assessment
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as fake_out:
            results._print_version_analysis_summary()
            output = fake_out.getvalue()
        
        # Should have version analysis section
        assert "📚 LIBRARY VERSION ANALYSIS" in output
        assert "Version analysis grouping:" in output
        assert "Firebase Cloud Messaging (19.0.0)" in output
        assert "6.0 years behind" in output
        assert "CRITICAL" in output
        
        # Should have summary statistics
        assert "SUMMARY:" in output
        assert "Total libraries analyzed: 2" in output
        assert "Critical risk: 1" in output
    
    def test_version_analysis_not_shown_without_security(self, mock_library_detection_result):
        """Test that version analysis is not shown without security assessment"""
        # Create FullAnalysisResults with library detection but NO security assessment
        results = FullAnalysisResults()
        results.library_detection = mock_library_detection_result
        results.security_assessment = None  # No security assessment
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as fake_out:
            results._print_version_analysis_summary()
            output = fake_out.getvalue()
        
        # Should NOT have version analysis section
        assert output == ""  # No output when security assessment is missing
    
    def test_version_analysis_not_shown_without_version_data(self, mock_security_assessment):
        """Test that version analysis is not shown when libraries have no version data"""
        # Create library without version analysis data
        library_no_version = DetectedLibrary(
            name="Some Library",
            package_name="some-lib",
            version="1.0.0",  # Has version but no analysis results
            detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
            category=LibraryCategory.UTILITY,
            confidence=0.95,
            evidence=["Test"],
            source=LibrarySource.PROPERTIES_FILES
        )
        # Note: No years_behind or security_risk attributes
        
        result = MagicMock()
        result.detected_libraries = [library_no_version]
        
        results = FullAnalysisResults()
        results.library_detection = result
        results.security_assessment = mock_security_assessment
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as fake_out:
            results._print_version_analysis_summary()
            output = fake_out.getvalue()
        
        # Should NOT have version analysis section (no analyzed libraries)
        assert output == ""
    
    def test_version_analysis_format_correctness(self, mock_libraries_with_versions, mock_security_assessment):
        """Test that version analysis output has correct format structure"""
        result = MagicMock()
        result.detected_libraries = mock_libraries_with_versions
        
        results = FullAnalysisResults()
        results.library_detection = result
        results.security_assessment = mock_security_assessment
        
        # Capture output
        with patch('sys.stdout', new=StringIO()) as fake_out:
            results._print_version_analysis_summary()
            output = fake_out.getvalue()
        
        lines = output.split('\n')
        
        # Check section header format
        assert any("📚 LIBRARY VERSION ANALYSIS" in line for line in lines)
        assert any("="*80 in line for line in lines)
        
        # Check risk section format
        assert any("⚠️  CRITICAL RISK LIBRARIES" in line for line in lines)
        assert any("└─" in line for line in lines)  # Recommendation indentation
        
        # Check summary format
        assert any("📊 SUMMARY:" in line for line in lines)
        assert any("Total libraries analyzed:" in line for line in lines)
    
    def test_full_summary_integration(self, mock_library_detection_result, mock_security_assessment):
        """Test that version analysis integrates correctly in full summary"""
        results = FullAnalysisResults()
        results.library_detection = mock_library_detection_result
        results.security_assessment = mock_security_assessment
        
        # Mock other required components for full summary
        results.apk_overview = None
        results.in_depth_analysis = None
        results.tracker_analysis = None
        results.behaviour_analysis = None
        results.apkid_analysis = None
        
        # Capture full summary output
        with patch('sys.stdout', new=StringIO()) as fake_out:
            with patch.object(results, '_print_summary_header'):
                with patch.object(results, '_print_summary_footer'):
                    results.print_analyst_summary()
            output = fake_out.getvalue()
        
        # Should contain both library detection and version analysis
        assert "📚 LIBRARY DETECTION" in output
        assert "📚 LIBRARY VERSION ANALYSIS" in output
        
        # Version analysis should come after library detection
        lib_detection_pos = output.find("📚 LIBRARY DETECTION")
        version_analysis_pos = output.find("📚 LIBRARY VERSION ANALYSIS")
        assert lib_detection_pos < version_analysis_pos


class TestOutputFormatRegression:
    """Regression tests for output format issues"""
    
    def test_version_analysis_not_in_execution_logs(self):
        """Test that version analysis doesn't appear during execution phase"""
        # This would be tested in integration tests by checking that
        # version analysis output appears only in summary section,
        # not mixed with module execution logs
        pass
    
    def test_section_separator_consistency(self):
        """Test that section separators are consistent"""
        # Mock basic result structure
        results = FullAnalysisResults()
        
        with patch('sys.stdout', new=StringIO()) as fake_out:
            results._print_summary_header()
            output = fake_out.getvalue()
        
        # Check for consistent separator usage
        assert "="*80 in output
        assert "📱 DEXRAY INSIGHT ANALYSIS SUMMARY" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])