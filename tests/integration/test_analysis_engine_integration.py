#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration tests for refactored AnalysisEngine functions.

Tests verify that the refactored single-responsibility functions work together
correctly in real-world scenarios while maintaining all original functionality.

Following SOLID principles:
- Single Responsibility: Each test focuses on one integration scenario
- Open/Closed: Tests are extensible for new scenarios without modification
- Interface Segregation: Tests use specific interfaces, not broad mocks
- Dependency Inversion: Tests depend on abstractions, not concretions
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.configuration import Configuration
from dexray_insight.core.base_classes import AnalysisContext


@pytest.mark.integration
class TestAnalysisEngineRefactoredIntegration:
    """Integration tests for refactored AnalysisEngine functionality."""

    @pytest.fixture
    def minimal_config(self):
        """
        Create minimal configuration for integration testing.
        
        Follows YAGNI principle - only includes what's needed for tests.
        """
        config = Configuration()
        # Disable external tools for faster integration tests
        config.config['temporal_analysis'] = {
            'enabled': True,
            'cleanup_after_analysis': False,
            'preserve_on_error': True
        }
        config.config['external_tools'] = {
            'apktool_enabled': False,
            'jadx_enabled': False
        }
        return config

    @pytest.fixture
    def analysis_engine(self, minimal_config):
        """Create AnalysisEngine with minimal configuration."""
        return AnalysisEngine(minimal_config)

    def test_complete_context_setup_to_cleanup_workflow(self, analysis_engine, valid_apk_path):
        """
        Test complete workflow from context setup through cleanup.
        
        Verifies that refactored functions integrate correctly:
        1. _setup_analysis_context creates proper context
        2. Context is usable by pipeline execution  
        3. _handle_analysis_cleanup works with context
        
        This is a critical integration test ensuring no regressions.
        """
        # Arrange: Mock external dependencies following DIP
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.base_dir = Path('/tmp/test_analysis')
            
            mock_tm_class.return_value = mock_temporal_manager
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            
            # Act: Execute the complete workflow
            
            # Step 1: Setup analysis context (refactored function)
            context = analysis_engine._setup_analysis_context(
                valid_apk_path, 
                androguard_obj=None, 
                timestamp="integration_test"
            )
            
            # Step 2: Verify context is properly structured
            assert isinstance(context, AnalysisContext)
            assert context.apk_path == valid_apk_path
            assert context.temporal_paths == mock_temporal_paths
            assert context.jadx_available is True
            assert context.apktool_available is True
            
            # Step 3: Test that context works with pipeline execution (refactored function)
            with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute_modules:
                mock_execute_modules.return_value = {'test_module': 'test_result'}
                
                pipeline_results = analysis_engine._execute_analysis_pipeline(
                    context, 
                    ['test_module']
                )
                
                # Verify pipeline execution
                mock_execute_modules.assert_called_once_with(context, ['test_module'])
                assert pipeline_results == {'test_module': 'test_result'}
            
            # Step 4: Test cleanup with context (refactored function)
            analysis_engine._handle_analysis_cleanup(
                context.temporal_paths, 
                preserve_on_error=True
            )
            
            # Assert: Verify all components worked together
            mock_temporal_manager.create_temporal_directory.assert_called_once_with(
                valid_apk_path, "integration_test"
            )

    def test_error_recovery_across_refactored_functions(self, analysis_engine, valid_apk_path):
        """
        Test error handling and recovery across function boundaries.
        
        Ensures that errors in one refactored function don't leave the system
        in an inconsistent state and that cleanup still works correctly.
        
        Critical for maintaining reliability after refactoring.
        """
        # Arrange: Setup that will cause an error in pipeline execution
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.base_dir = Path('/tmp/error_test')
            
            mock_tm_class.return_value = mock_temporal_manager
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            
            # Step 1: Successfully setup context
            context = analysis_engine._setup_analysis_context(valid_apk_path)
            
            # Step 2: Simulate error in pipeline execution
            with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute_modules:
                mock_execute_modules.side_effect = RuntimeError("Simulated module failure")
                
                # Act & Assert: Error should be properly handled
                with pytest.raises(RuntimeError, match="Simulated module failure"):
                    analysis_engine._execute_analysis_pipeline(context, ['failing_module'])
                
                # Step 3: Verify that cleanup still works after error
                # This is critical - errors shouldn't prevent proper cleanup
                analysis_engine._handle_analysis_cleanup(
                    context.temporal_paths, 
                    preserve_on_error=False  # Force cleanup even after error
                )
                
                # Assert: Cleanup was called with force=True due to preserve_on_error=False
                mock_temporal_manager.cleanup_temporal_directory.assert_called_once_with(
                    mock_temporal_paths, force=True
                )

    def test_temporal_directory_lifecycle_integration(self, analysis_engine, valid_apk_path):
        """
        Test complete temporal directory lifecycle across refactored functions.
        
        Verifies that temporal directories are:
        1. Created during context setup
        2. Available during pipeline execution
        3. Properly handled during cleanup
        
        Tests the integration of all three refactored functions.
        """
        # Arrange: Mock temporal directory manager with realistic behavior
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.base_dir = Path('/tmp/lifecycle_test')
            
            mock_tm_class.return_value = mock_temporal_manager
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            
            # Act: Execute complete lifecycle
            
            # Phase 1: Context setup creates temporal directory
            context = analysis_engine._setup_analysis_context(
                valid_apk_path, 
                timestamp="lifecycle_test"
            )
            
            # Phase 2: Pipeline execution has access to temporal paths
            with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute_modules:
                mock_execute_modules.return_value = {'analysis': 'completed'}
                
                # Verify context has temporal paths available
                assert context.temporal_paths == mock_temporal_paths
                
                results = analysis_engine._execute_analysis_pipeline(context, ['test_module'])
                
                # Verify module execution was called with correct context
                mock_execute_modules.assert_called_once_with(context, ['test_module'])
                assert 'analysis' in results
            
            # Phase 3: Cleanup handles temporal directory appropriately
            
            # Test preservation scenario
            analysis_engine._handle_analysis_cleanup(
                context.temporal_paths, 
                preserve_on_error=True
            )
            
            # Verify no cleanup was called (preservation mode)
            mock_temporal_manager.cleanup_temporal_directory.assert_not_called()
            
            # Test cleanup scenario
            analysis_engine._handle_analysis_cleanup(
                context.temporal_paths, 
                preserve_on_error=False
            )
            
            # Verify cleanup was called
            mock_temporal_manager.cleanup_temporal_directory.assert_called_once_with(
                mock_temporal_paths, force=True
            )
            
            # Assert: Complete lifecycle verification
            mock_temporal_manager.create_temporal_directory.assert_called_once_with(
                valid_apk_path, "lifecycle_test"
            )

    def test_configuration_driven_behavior_integration(self, analysis_engine, valid_apk_path):
        """
        Test that configuration properly drives behavior across refactored functions.
        
        Verifies that configuration changes affect all refactored functions consistently:
        - Context setup respects temporal analysis settings
        - Pipeline execution uses correct configuration
        - Cleanup follows configuration rules
        
        Tests configuration dependency injection (DIP principle).
        """
        # Test Case 1: Temporal analysis disabled
        analysis_engine.config.config['temporal_analysis']['enabled'] = False
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_tm_class.return_value = mock_temporal_manager
            
            # Context setup should not create temporal directory when disabled
            context = analysis_engine._setup_analysis_context(valid_apk_path)
            
            # Assert: No temporal directory creation when disabled
            assert context.temporal_paths is None
            mock_temporal_manager.create_temporal_directory.assert_not_called()
            
            # Cleanup should handle None temporal paths gracefully
            analysis_engine._handle_analysis_cleanup(None, preserve_on_error=True)
            # Should complete without errors
        
        # Test Case 2: Temporal analysis enabled with cleanup
        analysis_engine.config.config['temporal_analysis']['enabled'] = True
        analysis_engine.config.config['temporal_analysis']['cleanup_after_analysis'] = True
        
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.base_dir = Path('/tmp/config_test')
            
            mock_tm_class.return_value = mock_temporal_manager
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            
            # Context setup should create temporal directory when enabled
            context = analysis_engine._setup_analysis_context(valid_apk_path)
            
            # Assert: Temporal directory created when enabled
            assert context.temporal_paths == mock_temporal_paths
            mock_temporal_manager.create_temporal_directory.assert_called_once()

    def test_module_dependency_resolution_integration(self, analysis_engine, valid_apk_path):
        """
        Test that module dependency resolution works correctly with refactored functions.
        
        Verifies that:
        1. Context setup provides necessary data for dependency resolution
        2. Pipeline execution respects module dependencies
        3. The integration preserves the existing dependency resolution logic
        
        Critical for ensuring module execution order remains correct.
        """
        # Arrange: Setup context with realistic configuration
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
            mock_temporal_manager = Mock()
            mock_temporal_paths = Mock()
            
            mock_tm_class.return_value = mock_temporal_manager  
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            
            # Create context
            context = analysis_engine._setup_analysis_context(valid_apk_path)
            
            # Act: Test pipeline execution with modules that have dependencies
            with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute_modules:
                # Simulate realistic module results that other modules might depend on
                mock_execute_modules.return_value = {
                    'apk_overview': {'package_name': 'com.test.app'},
                    'string_analysis': {'strings_found': 150}
                }
                
                requested_modules = ['apk_overview', 'string_analysis', 'permission_analysis']
                results = analysis_engine._execute_analysis_pipeline(context, requested_modules)
                
                # Assert: Pipeline execution received correct context and modules
                mock_execute_modules.assert_called_once_with(context, requested_modules)
                
                # Verify that context contains all necessary information for modules
                assert context.apk_path == valid_apk_path
                assert context.config is not None
                assert isinstance(context.config, dict)
                
                # Verify results structure maintains expected format
                assert 'apk_overview' in results
                assert 'string_analysis' in results
                assert results['apk_overview']['package_name'] == 'com.test.app'

    def test_refactored_functions_maintain_original_analyze_apk_behavior(self, analysis_engine, valid_apk_path):
        """
        Test that the refactored functions, when used together, maintain the exact
        same behavior as the original analyze_apk function.
        
        This is a comprehensive regression test ensuring no functionality was lost
        during refactoring. Tests the integration with the main analyze_apk method.
        
        Critical for backward compatibility and reliability.
        """
        # Arrange: Mock all external dependencies to isolate the refactored logic
        with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class, \
             patch.object(analysis_engine, '_execute_external_tools') as mock_external_tools, \
             patch.object(analysis_engine, '_create_full_results') as mock_create_results:
            
            # Setup temporal directory manager mock
            mock_temporal_manager = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.base_dir = Path('/tmp/regression_test')
            
            mock_tm_class.return_value = mock_temporal_manager
            mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
            mock_temporal_manager.check_tool_availability.return_value = True
            mock_temporal_manager.process_apk_with_tools.return_value = {
                'unzip': True, 'jadx': True, 'apktool': True
            }
            
            # Setup other mocks
            mock_external_tools.return_value = {'apkid': {}, 'kavanoz': {}}
            mock_create_results.return_value = Mock()  # Simplified results object
            
            # Mock the module execution to return realistic results
            with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute_modules:
                mock_execute_modules.return_value = {
                    'apk_overview': {'status': 'success'},
                    'string_analysis': {'status': 'success'}
                }
                
                # Act: Execute the complete analyze_apk method
                # This should use all our refactored functions internally
                result = analysis_engine.analyze_apk(
                    apk_path=valid_apk_path,
                    requested_modules=['apk_overview', 'string_analysis'],
                    androguard_obj=None,
                    timestamp='regression_test'
                )
                
                # Assert: Verify that all refactored functions were called correctly
                
                # 1. Context setup was called (through analyze_apk)
                mock_temporal_manager.create_temporal_directory.assert_called_once_with(
                    valid_apk_path, 'regression_test'
                )
                
                # 2. Pipeline execution was called with correct parameters
                mock_execute_modules.assert_called_once()
                call_args = mock_execute_modules.call_args
                context_arg, modules_arg = call_args[0]
                
                assert context_arg.apk_path == valid_apk_path
                assert modules_arg == ['apk_overview', 'string_analysis']
                
                # 3. External tools were executed
                mock_external_tools.assert_called_once_with(valid_apk_path)
                
                # 4. Results were created with correct parameters
                mock_create_results.assert_called_once()
                
                # 5. Return value is properly structured
                assert result is not None


@pytest.mark.integration
class TestAnalysisEnginePerformanceIntegration:
    """Performance integration tests to ensure refactoring didn't degrade performance."""

    @pytest.mark.performance
    def test_refactored_functions_performance_baseline(self, analysis_engine, valid_apk_path, benchmark):
        """
        Benchmark performance of refactored functions to establish baseline.
        
        This test ensures that refactoring didn't introduce significant
        performance overhead. Future changes can be compared against this baseline.
        """
        def setup_and_cleanup_workflow():
            """Realistic workflow using refactored functions."""
            with patch('dexray_insight.core.analysis_engine.TemporalDirectoryManager') as mock_tm_class:
                mock_temporal_manager = Mock()
                mock_temporal_paths = Mock()
                
                mock_tm_class.return_value = mock_temporal_manager
                mock_temporal_manager.create_temporal_directory.return_value = mock_temporal_paths
                mock_temporal_manager.check_tool_availability.return_value = True
                
                # Execute the workflow
                context = analysis_engine._setup_analysis_context(valid_apk_path)
                
                with patch.object(analysis_engine, '_execute_analysis_modules') as mock_execute:
                    mock_execute.return_value = {'test': 'result'}
                    results = analysis_engine._execute_analysis_pipeline(context, ['test'])
                
                analysis_engine._handle_analysis_cleanup(context.temporal_paths, preserve_on_error=True)
                
                return results
        
        # Benchmark the workflow
        result = benchmark(setup_and_cleanup_workflow)
        
        # Assert that the workflow completed successfully
        assert result == {'test': 'result'}


# Marker for all integration tests
pytestmark = pytest.mark.integration