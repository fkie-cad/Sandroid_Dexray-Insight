#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for refactored AnalysisEngine functions following TDD principles.

This module contains tests for the newly refactored single-responsibility functions
extracted from the original multi-purpose methods in AnalysisEngine.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from dexray_insight.core.base_classes import AnalysisContext


class TestSetupAnalysisContext:
    """Tests for _setup_analysis_context function (TDD - Red Phase)"""

    def test_setup_analysis_context_creates_valid_context(self, analysis_engine, valid_apk_path):
        """
        Test that _setup_analysis_context creates a valid AnalysisContext
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        androguard_obj = Mock()
        timestamp = "20241201_120000"
        
        # Act
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_tm = Mock()
            mock_tm_class.return_value = mock_tm
            mock_tm.create_temporal_directory.return_value = Mock()
            mock_tm.check_tool_availability.return_value = True
            
            # This will fail initially - RED phase
            context = analysis_engine._setup_analysis_context(
                valid_apk_path, androguard_obj, timestamp
            )
        
        # Assert
        assert isinstance(context, AnalysisContext)
        assert context.apk_path == valid_apk_path
        assert context.androguard_obj == androguard_obj
        assert context.config is not None
        assert hasattr(context, 'temporal_paths')
        assert hasattr(context, 'jadx_available')
        assert hasattr(context, 'apktool_available')

    def test_setup_analysis_context_handles_missing_apk(self, analysis_engine):
        """
        Test that _setup_analysis_context handles missing APK file gracefully
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        missing_apk_path = "/nonexistent/path/app.apk"
        androguard_obj = None
        timestamp = None
        
        # Act & Assert
        with pytest.raises(FileNotFoundError):
            analysis_engine._setup_analysis_context(
                missing_apk_path, androguard_obj, timestamp
            )

    def test_setup_analysis_context_creates_temporal_directories(self, analysis_engine, valid_apk_path):
        """
        Test that _setup_analysis_context properly creates temporal directories when enabled
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        androguard_obj = Mock()
        timestamp = "test_timestamp"
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_tm_class.return_value = mock_temporal_manager
            mock_temporal_paths = Mock()
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            
            # Act
            context = analysis_engine._setup_analysis_context(
                valid_apk_path, androguard_obj, timestamp
            )
            
            # Assert
            mock_temporal_manager.create_temporal_directory.assert_called_once_with(
                valid_apk_path, timestamp
            )
            assert context.temporal_paths == mock_temporal_paths

    def test_setup_analysis_context_handles_temporal_disabled(self, analysis_engine, valid_apk_path):
        """
        Test that _setup_analysis_context works when temporal analysis is disabled
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        # Configure temporal analysis as disabled
        analysis_engine.config.config['temporal_analysis'] = {'enabled': False}
        androguard_obj = Mock()
        timestamp = None
        
        # Act
        context = analysis_engine._setup_analysis_context(
            valid_apk_path, androguard_obj, timestamp
        )
        
        # Assert
        assert context.temporal_paths is None
        assert isinstance(context, AnalysisContext)

    def test_setup_analysis_context_preserves_existing_androguard_obj(self, analysis_engine, valid_apk_path):
        """
        Test that _setup_analysis_context preserves existing androguard object
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        existing_androguard_obj = Mock()
        existing_androguard_obj.some_attribute = "test_value"
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager'):
            # Act
            context = analysis_engine._setup_analysis_context(
                valid_apk_path, existing_androguard_obj, None
            )
            
            # Assert
            assert context.androguard_obj is existing_androguard_obj
            assert context.androguard_obj.some_attribute == "test_value"


class TestExecuteAnalysisPipeline:
    """Tests for _execute_analysis_pipeline function (TDD - Red Phase)"""

    def test_execute_analysis_pipeline_runs_requested_modules(self, analysis_engine):
        """
        Test that _execute_analysis_pipeline executes only requested modules
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        context = Mock(spec=AnalysisContext)
        requested_modules = ["apk_overview", "string_analysis"]
        
        with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute:
            mock_execute.return_value = {"test": "results"}
            
            # Act
            results = analysis_engine._execute_analysis_pipeline(context, requested_modules)
            
            # Assert
            mock_execute.assert_called_once_with(context, requested_modules)
            assert results == {"test": "results"}

    def test_execute_analysis_pipeline_handles_module_failures(self, analysis_engine):
        """
        Test that _execute_analysis_pipeline handles individual module failures gracefully
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        context = Mock(spec=AnalysisContext)
        requested_modules = ["apk_overview", "failing_module"]
        
        with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute:
            mock_execute.side_effect = Exception("Module failed")
            
            # Act & Assert
            with pytest.raises(Exception) as exc_info:
                analysis_engine._execute_analysis_pipeline(context, requested_modules)
            
            assert "Module failed" in str(exc_info.value)

    def test_execute_analysis_pipeline_respects_dependencies(self, analysis_engine):
        """
        Test that _execute_analysis_pipeline respects module dependencies
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        context = Mock(spec=AnalysisContext)
        requested_modules = ["string_analysis", "apk_overview"]  # string_analysis depends on apk_overview
        
        with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute:
            mock_execute.return_value = {"dependency_test": "passed"}
            
            # Act
            result = analysis_engine._execute_analysis_pipeline(context, requested_modules)
            
            # Assert
            mock_execute.assert_called_once()
            assert result["dependency_test"] == "passed"


class TestHandleAnalysisCleanup:
    """Tests for _handle_analysis_cleanup function (TDD - Red Phase)"""

    def test_handle_analysis_cleanup_preserves_on_error(self, analysis_engine):
        """
        Test that _handle_analysis_cleanup preserves temporal files on error when configured
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        mock_temporal_paths = Mock()
        preserve_on_error = True
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_tm_class.return_value = mock_temporal_manager
            analysis_engine.temporal_manager = mock_temporal_manager
            
            # Act
            analysis_engine._handle_analysis_cleanup(mock_temporal_paths, preserve_on_error)
            
            # Assert
            # Should not call cleanup when preserve_on_error is True
            mock_temporal_manager.cleanup_temporal_directory.assert_not_called()

    def test_handle_analysis_cleanup_removes_temp_files_on_success(self, analysis_engine):
        """
        Test that _handle_analysis_cleanup removes temporary files on successful completion
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        mock_temporal_paths = Mock()
        preserve_on_error = False
        
        # Mock the config to enable cleanup
        analysis_engine.config.config['temporal_analysis'] = {'cleanup_after_analysis': True}
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_tm_class.return_value = mock_temporal_manager
            analysis_engine.temporal_manager = mock_temporal_manager
            
            # Act
            analysis_engine._handle_analysis_cleanup(mock_temporal_paths, preserve_on_error)
            
            # Assert
            mock_temporal_manager.cleanup_temporal_directory.assert_called_once_with(
                mock_temporal_paths, force=True
            )

    def test_handle_analysis_cleanup_handles_none_temporal_paths(self, analysis_engine):
        """
        Test that _handle_analysis_cleanup handles None temporal_paths gracefully
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        temporal_paths = None
        preserve_on_error = True
        
        # Act - should not raise any exception
        analysis_engine._handle_analysis_cleanup(temporal_paths, preserve_on_error)
        
        # Assert - no exception should be raised
        assert True  # If we get here, the test passed

    def test_handle_analysis_cleanup_forces_cleanup_on_error_when_configured(self, analysis_engine):
        """
        Test that _handle_analysis_cleanup can force cleanup even on error when configured
        
        RED: This test will fail initially as the function doesn't exist yet
        """
        # Arrange
        mock_temporal_paths = Mock()
        preserve_on_error = False  # Force cleanup
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_tm_class.return_value = mock_temporal_manager
            analysis_engine.temporal_manager = mock_temporal_manager
            
            # Act
            analysis_engine._handle_analysis_cleanup(mock_temporal_paths, preserve_on_error)
            
            # Assert
            mock_temporal_manager.cleanup_temporal_directory.assert_called_once_with(
                mock_temporal_paths, force=True
            )


# Mark these as refactored tests for our CI pipeline
pytestmark = pytest.mark.refactored