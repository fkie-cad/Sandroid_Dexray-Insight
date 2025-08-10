#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simplified TDD tests for refactored FullAnalysisResults.print_analyst_summary() function.
Avoids circular import issues by using direct module imports.
"""

import pytest
from unittest.mock import Mock, patch
from io import StringIO
import sys


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
class TestFullAnalysisResultsRefactored:
    """
    TDD tests for refactored print_analyst_summary functions.
    Testing approach: Import at test time to avoid circular imports.
    """
    
    def test_print_summary_header_function_exists(self):
        """
        Test that _print_summary_header function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Import here to avoid circular import
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        # Arrange
        results = FullAnalysisResults()
        
        # Act & Assert - This will fail initially (RED phase)
        assert hasattr(results, '_print_summary_header'), "Function _print_summary_header should exist"
        
        # Should be callable
        assert callable(getattr(results, '_print_summary_header')), "Function should be callable"
    
    def test_print_apk_information_function_exists(self):
        """
        Test that _print_apk_information function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_apk_information'), "Function _print_apk_information should exist"
        assert callable(getattr(results, '_print_apk_information')), "Function should be callable"
    
    def test_print_permissions_summary_function_exists(self):
        """
        Test that _print_permissions_summary function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_permissions_summary'), "Function _print_permissions_summary should exist"
        assert callable(getattr(results, '_print_permissions_summary')), "Function should be callable"
    
    def test_print_string_analysis_summary_function_exists(self):
        """
        Test that _print_string_analysis_summary function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_string_analysis_summary'), "Function _print_string_analysis_summary should exist"
        assert callable(getattr(results, '_print_string_analysis_summary')), "Function should be callable"
    
    def test_print_security_assessment_summary_function_exists(self):
        """
        Test that _print_security_assessment_summary function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_security_assessment_summary'), "Function _print_security_assessment_summary should exist"
        assert callable(getattr(results, '_print_security_assessment_summary')), "Function should be callable"
    
    def test_print_tool_analysis_summary_function_exists(self):
        """
        Test that _print_tool_analysis_summary function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_tool_analysis_summary'), "Function _print_tool_analysis_summary should exist"
        assert callable(getattr(results, '_print_tool_analysis_summary')), "Function should be callable"
    
    def test_print_component_behavior_summary_function_exists(self):
        """
        Test that _print_component_behavior_summary function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_component_behavior_summary'), "Function _print_component_behavior_summary should exist"
        assert callable(getattr(results, '_print_component_behavior_summary')), "Function should be callable"
    
    def test_print_summary_footer_function_exists(self):
        """
        Test that _print_summary_footer function exists after refactoring.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        results = FullAnalysisResults()
        assert hasattr(results, '_print_summary_footer'), "Function _print_summary_footer should exist"
        assert callable(getattr(results, '_print_summary_footer')), "Function should be callable"
    
    def test_refactored_print_analyst_summary_maintains_functionality(self):
        """
        Integration test: Refactored print_analyst_summary should still work.
        
        This test verifies that the refactored version maintains the same public interface.
        """
        from dexray_insight.results.FullAnalysisResults import FullAnalysisResults
        
        # Arrange
        results = FullAnalysisResults()
        
        # Act - Should not crash (will call refactored version once implemented)
        output = capture_print_output(results.print_analyst_summary)
        
        # Assert - Should produce some output
        assert len(output) > 0, "Should produce some output"
        assert "DEXRAY INSIGHT ANALYSIS SUMMARY" in output, "Should contain summary header"


# Mark all tests in this module as phase3 refactored tests
pytestmark = [pytest.mark.refactored, pytest.mark.phase3]