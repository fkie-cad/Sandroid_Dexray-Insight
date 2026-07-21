#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TDD tests for multidex regression fix.

This test ensures that the multidex handling works correctly after refactoring.
The critical issue was that multidex APKs were only analyzing the first DEX file
instead of all available DEX files.

Note: AndroguardObj construction now mirrors AnalyzeAPK internally (APK + one
DalvikVMFormat/DEX per get_all_dex() entry) while deferring the expensive
Analysis.create_xref() build. These tests therefore patch the androguard building
blocks (APK/DEX/Analysis/DecompilerDAD) rather than the old AnalyzeAPK helper.
"""

import os
import tempfile
import zipfile
from contextlib import ExitStack
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.core.configuration import Configuration
from dexray_insight.modules.string_analysis import StringAnalysisModule
from dexray_insight.Utils.androguardObjClass import AndroguardObj

_MOD = "dexray_insight.Utils.androguardObjClass"


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
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp_file:
            apk_path = tmp_file.name

            # Create mock zip with multiple DEX files
            with zipfile.ZipFile(tmp_file.name, "w") as zip_file:
                zip_file.writestr("AndroidManifest.xml", "<manifest/>")
                for i in range(num_dex_files):
                    zip_file.writestr(f'classes{i+1 if i > 0 else ""}.dex', b"mock_dex_data")

        # Create mock DEX objects
        mock_dex_objects = []
        for i in range(num_dex_files):
            mock_dex = Mock()
            mock_dex.get_strings.return_value = [f"string_{i}_{j}" for j in range(100 + i * 50)]
            mock_dex_objects.append(mock_dex)

        return apk_path, mock_dex_objects

    def _enter_androguard_patches(self, stack: ExitStack, mock_dex_objects):
        """Patch the androguard building blocks used by AndroguardObj.__init__.

        Returns the mock APK object. Each DEX(...) call yields the next mock DEX so
        that get_androguard_dex() returns exactly the provided objects, in order.
        """
        mock_apk = Mock()
        mock_apk.get_all_dex.return_value = [f"dexbytes_{i}".encode() for i in range(len(mock_dex_objects))]
        mock_apk.get_target_sdk_version.return_value = 21
        stack.enter_context(patch(f"{_MOD}.androguard_apk_module.APK", return_value=mock_apk))
        stack.enter_context(patch(f"{_MOD}.androguard_dex_module.DEX", side_effect=list(mock_dex_objects)))
        stack.enter_context(patch(f"{_MOD}.Analysis", return_value=Mock()))
        stack.enter_context(patch(f"{_MOD}.androguard_decompiler.DecompilerDAD", return_value=Mock()))
        return mock_apk

    def test_androguard_object_handles_multidex(self):
        """
        Test that AndroguardObj correctly initializes with all DEX files in a multidex APK.

        This is the core test for the regression - ensuring that androguard returns
        all DEX files, not just the first one.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=5)

        # Act
        with ExitStack() as stack:
            self._enter_androguard_patches(stack, mock_dex_objects)
            androguard_obj = AndroguardObj(apk_path)

        # Assert
        dex_obj = androguard_obj.get_androguard_dex()
        assert len(dex_obj) == 5, f"Expected 5 DEX objects, got {len(dex_obj)}"

        # Verify all DEX objects are accessible
        for i, dex in enumerate(dex_obj):
            strings = dex.get_strings()
            assert len(strings) > 0, f"DEX {i+1} should have strings"
            assert f"string_{i}_0" in strings, f"DEX {i+1} should have expected string pattern"

        # Cleanup
        os.unlink(apk_path)

    def test_string_analysis_processes_all_dex_files(self):
        """
        Test that string analysis module processes all DEX files in multidex APK.

        This tests the integration between androguard object and string analysis,
        ensuring that all DEX files are processed for string extraction.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=3)

        with ExitStack() as stack:
            self._enter_androguard_patches(stack, mock_dex_objects)
            androguard_obj = AndroguardObj(apk_path)

        # Create analysis context (caching left at default None so extraction is live)
        config = Configuration()
        context = AnalysisContext(
            apk_path=apk_path, config=config.to_dict(), androguard_obj=androguard_obj, temporal_paths=None
        )

        # Create string analysis module
        string_module = StringAnalysisModule(config.get_module_config("string_analysis"))

        # Act
        result = string_module.analyze(apk_path, context)

        # Assert
        assert result.status.value == "success", f"String analysis failed: {result.error_message}"

        # Verify that strings from all DEX files were processed
        # Each mock DEX has strings with pattern 'string_{dex_index}_{string_index}'
        all_strings = result.all_strings

        # Should have strings from all 3 DEX files
        dex_0_strings = [s for s in all_strings if s.startswith("string_0_")]
        dex_1_strings = [s for s in all_strings if s.startswith("string_1_")]
        dex_2_strings = [s for s in all_strings if s.startswith("string_2_")]

        assert len(dex_0_strings) > 0, "Should have strings from DEX 0"
        assert len(dex_1_strings) > 0, "Should have strings from DEX 1"
        assert len(dex_2_strings) > 0, "Should have strings from DEX 2"

        # Cleanup
        os.unlink(apk_path)

    def test_analysis_engine_multidex_integration(self):
        """
        Test that AnalysisEngine correctly handles multidex APK through the refactored code.

        This is the end-to-end integration test ensuring the refactored analysis engine
        properly processes all DEX files in a multidex APK.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=4)

        # Create configuration and analysis engine (disable caching for test isolation:
        # the mock APK content is constant, so its MD5 would otherwise collide across runs)
        config = Configuration()
        config.config["modules"]["string_analysis"]["enabled"] = True
        config.config["caching"]["enabled"] = False
        engine = AnalysisEngine(config)

        with ExitStack() as stack:
            self._enter_androguard_patches(stack, mock_dex_objects)
            androguard_obj = AndroguardObj(apk_path)

            # Act - Run analysis through refactored engine
            results = engine.analyze_apk(
                apk_path, requested_modules=["string_analysis"], androguard_obj=androguard_obj
            )

        # Assert
        assert results is not None, "Analysis should not return None"

        # Check that string analysis was performed
        string_result = results.in_depth_analysis
        assert string_result is not None, "Should have string analysis results"

        # Cleanup
        os.unlink(apk_path)

    def test_single_dex_backward_compatibility(self):
        """
        Test that single DEX APKs still work correctly after multidex fix.

        This ensures we didn't break single-DEX APK handling while fixing multidex.
        """
        # Arrange
        apk_path, mock_dex_objects = self.create_mock_multidex_apk(num_dex_files=1)

        # Act
        with ExitStack() as stack:
            self._enter_androguard_patches(stack, mock_dex_objects)
            androguard_obj = AndroguardObj(apk_path)

        # Assert
        dex_obj = androguard_obj.get_androguard_dex()
        assert len(dex_obj) == 1, f"Single DEX APK should have 1 DEX object, got {len(dex_obj)}"

        # Verify the single DEX is accessible
        strings = dex_obj[0].get_strings()
        assert len(strings) > 0, "Single DEX should have strings"

        # Cleanup
        os.unlink(apk_path)

    def test_androguard_error_handling(self):
        """
        Test that androguard errors are handled gracefully.
        """
        # Arrange
        apk_path, _ = self.create_mock_multidex_apk(num_dex_files=2)

        # Act & Assert - a failure building the APK propagates
        with ExitStack() as stack:
            stack.enter_context(
                patch(f"{_MOD}.androguard_apk_module.APK", side_effect=Exception("Androguard analysis failed"))
            )
            with pytest.raises(Exception, match="Androguard analysis failed"):
                AndroguardObj(apk_path)

        # Cleanup
        os.unlink(apk_path)

    def test_empty_dex_handling(self):
        """
        Test handling of APKs with no DEX files (edge case).
        """
        # Arrange
        apk_path, _ = self.create_mock_multidex_apk(num_dex_files=0)

        # Act
        with ExitStack() as stack:
            self._enter_androguard_patches(stack, [])
            androguard_obj = AndroguardObj(apk_path)

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


# Mark all tests in this module as multidex regression tests
pytestmark = [pytest.mark.multidex, pytest.mark.refactored]
