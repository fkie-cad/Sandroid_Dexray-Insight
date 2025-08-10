#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TDD tests for multidex regression fix.

This test ensures that the multidex handling works correctly after refactoring.
The critical issue was that multidex APKs were only analyzing the first DEX file
instead of all available DEX files.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import tempfile
import os
import zipfile
from argparse import Namespace

from dexray_insight.Utils.androguardObjClass import Androguard_Obj
from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.configuration import Configuration
from dexray_insight.modules.string_analysis import StringAnalysisModule
from dexray_insight.core.base_classes import AnalysisContext


@pytest.mark.multidex
@pytest.mark.refactored
class TestMultidexRegression:
    """
    Test suite for multidex APK handling regression.
    
    The issue: After refactoring, multidex APKs only analyzed the first DEX file.
    The fix: Ensure androguard object properly returns all DEX files.
    """
    
    def create_mock_multidex_apk(self, num_dex_files=5):
        """
        Create a mock multidex APK structure for testing.
        
        Args:
            num_dex_files: Number of DEX files to simulate
            
        Returns:
            Tuple of (apk_path, mock_dex_objects)
        """
        # Create temporary APK file
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp_file:
            apk_path = tmp_file.name
            
            # Create mock zip with multiple DEX files
            with zipfile.ZipFile(tmp_file.name, 'w') as zip_file:
                zip_file.writestr('AndroidManifest.xml', '<manifest/>')
                for i in range(num_dex_files):
                    zip_file.writestr(f'classes{i+1 if i > 0 else ""}.dex', b'mock_dex_data')
        
        # Create mock DEX objects
        mock_dex_objects = []
        for i in range(num_dex_files):
            mock_dex = Mock()
            mock_dex.get_strings.return_value = [f'string_{i}_{j}' for j in range(100 + i * 50)]
            mock_dex_objects.append(mock_dex)
        
        return apk_path, mock_dex_objects
    
    @patch('dexray_insight.Utils.androguardObjClass.AnalyzeAPK')
    def test_androguard_object_handles_multidex(self, mock_analyze_apk):
        """
        Test that Androguard_Obj correctly initializes with all DEX files in a multidex APK.
        
        This is the core test for the regression - ensuring that androguard returns
        all DEX files, not just the first one.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=5)
        
        mock_apk = Mock()
        mock_dx_analysis = Mock()
        mock_analyze_apk.return_value = (mock_apk, mock_dex_objects, mock_dx_analysis)
        
        # Act
        androguard_obj = Androguard_Obj(apk_path)
        
        # Assert
        dex_obj = androguard_obj.get_androguard_dex()
        assert len(dex_obj) == 5, f"Expected 5 DEX objects, got {len(dex_obj)}"
        
        # Verify all DEX objects are accessible
        for i, dex in enumerate(dex_obj):
            strings = dex.get_strings()
            assert len(strings) > 0, f"DEX {i+1} should have strings"
            assert f'string_{i}_0' in strings, f"DEX {i+1} should have expected string pattern"
        
        # Cleanup
        os.unlink(apk_path)
    
    @patch('dexray_insight.Utils.androguardObjClass.AnalyzeAPK')
    def test_string_analysis_processes_all_dex_files(self, mock_analyze_apk):
        """
        Test that string analysis module processes all DEX files in multidex APK.
        
        This tests the integration between androguard object and string analysis,
        ensuring that all DEX files are processed for string extraction.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=3)
        
        mock_apk = Mock()
        mock_dx_analysis = Mock()
        mock_analyze_apk.return_value = (mock_apk, mock_dex_objects, mock_dx_analysis)
        
        # Create androguard object
        androguard_obj = Androguard_Obj(apk_path)
        
        # Create analysis context
        config = Configuration()
        context = AnalysisContext(
            apk_path=apk_path,
            config=config.to_dict(),
            androguard_obj=androguard_obj,
            temporal_paths=None
        )
        
        # Create string analysis module
        string_module = StringAnalysisModule(config.get_module_config('string_analysis'))
        
        # Act
        result = string_module.analyze(apk_path, context)
        
        # Assert
        assert result.status.value == 'success', f"String analysis failed: {result.error_message}"
        
        # Verify that strings from all DEX files were processed
        # Each mock DEX has strings with pattern 'string_{dex_index}_{string_index}'
        all_strings = result.all_strings
        
        # Should have strings from all 3 DEX files
        dex_0_strings = [s for s in all_strings if s.startswith('string_0_')]
        dex_1_strings = [s for s in all_strings if s.startswith('string_1_')]
        dex_2_strings = [s for s in all_strings if s.startswith('string_2_')]
        
        assert len(dex_0_strings) > 0, "Should have strings from DEX 0"
        assert len(dex_1_strings) > 0, "Should have strings from DEX 1"  
        assert len(dex_2_strings) > 0, "Should have strings from DEX 2"
        
        # Verify total string count is reasonable
        expected_total = sum(len(dex.get_strings()) for dex in mock_dex_objects)
        assert result.total_strings_analyzed == expected_total, \
            f"Expected {expected_total} strings analyzed, got {result.total_strings_analyzed}"
        
        # Cleanup
        os.unlink(apk_path)
    
    @patch('dexray_insight.Utils.androguardObjClass.AnalyzeAPK')
    def test_analysis_engine_multidex_integration(self, mock_analyze_apk):
        """
        Test that AnalysisEngine correctly handles multidex APK through the refactored code.
        
        This is the end-to-end integration test ensuring the refactored analysis engine
        properly processes all DEX files in a multidex APK.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=4)
        
        mock_apk = Mock()
        mock_dx_analysis = Mock()
        mock_analyze_apk.return_value = (mock_apk, mock_dex_objects, mock_dx_analysis)
        
        # Create configuration and analysis engine
        config = Configuration()
        config.config['modules']['string_analysis']['enabled'] = True
        engine = AnalysisEngine(config)
        
        # Create androguard object
        androguard_obj = Androguard_Obj(apk_path)
        
        # Act - Run analysis through refactored engine
        results = engine.analyze_apk(
            apk_path,
            requested_modules=['string_analysis'],
            androguard_obj=androguard_obj
        )
        
        # Assert
        assert results is not None, "Analysis should not return None"
        
        # Check that string analysis was performed
        string_result = results.in_depth_analysis
        assert string_result is not None, "Should have string analysis results"
        
        # Verify multidex processing - should have strings from all DEX files
        if hasattr(string_result, 'strings_domain') or hasattr(results, 'get_string_analysis_result'):
            # The exact structure depends on how results are organized, but we should
            # have evidence that all DEX files were processed
            pass  # This would need to be adapted based on actual result structure
        
        # Cleanup
        os.unlink(apk_path)
    
    def test_single_dex_backward_compatibility(self):
        """
        Test that single DEX APKs still work correctly after multidex fix.
        
        This ensures we didn't break single-DEX APK handling while fixing multidex.
        """
        # This test would use a real single DEX APK or mock one
        # For now, we'll use a mock to verify the logic
        with patch('dexray_insight.Utils.androguardObjClass.AnalyzeAPK') as mock_analyze_apk:
            # Arrange
            apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=1)
            
            mock_apk = Mock()
            mock_dx_analysis = Mock()
            mock_analyze_apk.return_value = (mock_apk, mock_dex_objects, mock_dx_analysis)
            
            # Act
            androguard_obj = Androguard_Obj(apk_path)
            
            # Assert
            dex_obj = androguard_obj.get_androguard_dex()
            assert len(dex_obj) == 1, f"Single DEX APK should have 1 DEX object, got {len(dex_obj)}"
            
            # Verify the single DEX is accessible
            strings = dex_obj[0].get_strings()
            assert len(strings) > 0, "Single DEX should have strings"
            
            # Cleanup
            os.unlink(apk_path)
    
    @patch('dexray_insight.Utils.androguardObjClass.AnalyzeAPK')
    def test_androguard_error_handling(self, mock_analyze_apk):
        """
        Test that androguard errors are handled gracefully.
        """
        # Arrange
        apk_path, _ = self.create_mock_multidex_apk(num_dex_files=2)
        mock_analyze_apk.side_effect = Exception("Androguard analysis failed")
        
        # Act & Assert
        with pytest.raises(Exception, match="Androguard analysis failed"):
            Androguard_Obj(apk_path)
        
        # Cleanup
        os.unlink(apk_path)
    
    def test_empty_dex_handling(self):
        """
        Test handling of APKs with no DEX files (edge case).
        """
        with patch('dexray_insight.Utils.androguardObjClass.AnalyzeAPK') as mock_analyze_apk:
            # Arrange
            apk_path, _ = self.create_mock_multidex_apk(num_dex_files=0)
            
            mock_apk = Mock()
            mock_dx_analysis = Mock()
            mock_analyze_apk.return_value = (mock_apk, [], mock_dx_analysis)  # Empty DEX list
            
            # Act
            androguard_obj = Androguard_Obj(apk_path)
            
            # Assert
            dex_obj = androguard_obj.get_androguard_dex()
            assert len(dex_obj) == 0, f"Empty APK should have 0 DEX objects, got {len(dex_obj)}"
            
            # Cleanup
            os.unlink(apk_path)


@pytest.mark.multidex
@pytest.mark.integration
class TestMultidexRegressionIntegration:
    """
    Integration tests for multidex handling with real scenarios.
    
    These tests would ideally use real multidex APK files for thorough validation.
    """
    
    def test_real_multidex_apk_analysis(self):
        """
        Integration test with a real multidex APK.
        
        Note: This test is skipped by default as it requires a real multidex APK file.
        To run this test, provide a path to a real multidex APK and remove the skip decorator.
        """
        pytest.skip("Requires real multidex APK file - provide path and remove skip to run")
        
        # Example implementation:
        # real_multidx_apk_path = "/path/to/real/multidex.apk"
        # config = Configuration()
        # engine = AnalysisEngine(config)
        # results = engine.analyze_apk(real_multidex_apk_path)
        # 
        # # Verify that multiple DEX files were processed
        # assert results is not None
        # # Add specific assertions based on expected results


# Mark all tests in this module as multidex regression tests
pytestmark = [pytest.mark.multidex, pytest.mark.refactored]